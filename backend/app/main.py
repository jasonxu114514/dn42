from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.orm import Session

from app.auth.kioubit import KioubitAuthError, KioubitVerifier
from app.auth.service import consume_challenge, create_challenge, upsert_user_from_kioubit
from app.auth.session import current_user, login_user, logout_user
from app.api.telegram import router as telegram_router
from app.config import get_settings
from app.db.init_db import create_schema, seed_defaults
from app.db.models import LGQuery, Node, PeerRequest, utcnow
from app.db.session import SessionLocal, get_db
from app.lg.client import AgentClient
from app.lg.validation import validate_query_type, validate_target
from app.peer.config import render_operator_config, render_user_config
from app.peer.deploy import apply_deploy_result, deploy_peer
from app.peer.validation import asn_link_local_address, normalize_link_local_address

settings = get_settings()
templates = Jinja2Templates(directory="app/templates")
app = FastAPI(title=settings.app_name)
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(telegram_router)


@app.on_event("startup")
def startup() -> None:
    create_schema()
    db = SessionLocal()
    try:
        seed_defaults(db, settings)
    finally:
        db.close()


def render(request: Request, name: str, context: dict | None = None) -> HTMLResponse:
    db = SessionLocal()
    try:
        user = current_user(request, db)
    finally:
        db.close()
    base = {"request": request, "settings": settings, "user": user}
    if context:
        base.update(context)
    return templates.TemplateResponse(request=request, name=name, context=base)


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    nodes = db.query(Node).filter(Node.enabled.is_(True)).order_by(Node.name).all()
    return render(request, "index.html", {"nodes": nodes})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    challenge = create_challenge(db, purpose="web")
    return render(
        request,
        "login.html",
        {
            "return_url": f"{settings.base_url}/auth/kioubit/callback",
            "token": challenge.token,
        },
    )


@app.get("/logout")
def logout(request: Request) -> RedirectResponse:
    logout_user(request)
    return RedirectResponse("/", status_code=303)


@app.get("/auth/kioubit/callback")
def kioubit_callback(
    request: Request,
    params: str,
    signature: str,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    verifier = KioubitVerifier(settings.kioubit_public_key_path, settings.auth_domain)
    try:
        data = verifier.verify(params=params, signature=signature)
        consume_challenge(db, data.get("user_token", ""), purpose="web")
        user = upsert_user_from_kioubit(db, data, settings)
    except (KioubitAuthError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    login_user(request, user)
    return RedirectResponse("/portal", status_code=303)


@app.get("/telegram/auth", response_class=HTMLResponse)
def telegram_auth_page(
    request: Request,
    token: str,
) -> HTMLResponse:
    return render(
        request,
        "telegram_auth.html",
        {
            "return_url": f"{settings.base_url}/telegram/auth?token={token}",
            "token": token,
        },
    )


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    nodes = db.query(Node).filter(Node.enabled.is_(True)).order_by(Node.name).all()
    peers = (
        db.query(PeerRequest)
        .filter(PeerRequest.user_id == user.id)
        .order_by(PeerRequest.created_at.desc())
        .all()
    )
    try:
        default_peer_link_address = asn_link_local_address(user.primary_asn)
    except ValueError:
        default_peer_link_address = ""
    try:
        default_local_link_address = asn_link_local_address(settings.local_asn)
    except ValueError:
        default_local_link_address = ""
    return render(
        request,
        "portal.html",
        {
            "nodes": nodes,
            "peers": peers,
            "default_local_link_address": default_local_link_address,
            "default_peer_link_address": default_peer_link_address,
        },
    )


@app.post("/portal/peers")
def create_peer_request(
    request: Request,
    node_id: int = Form(...),
    endpoint: str = Form(...),
    wg_public_key: str = Form(...),
    local_link_address: str = Form(...),
    peer_link_address: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    node = db.query(Node).filter(Node.id == node_id, Node.enabled.is_(True)).one_or_none()
    if node is None:
        raise HTTPException(status_code=400, detail="Unknown node")
    if len(wg_public_key.strip()) < 32:
        raise HTTPException(status_code=400, detail="WireGuard public key looks too short")
    try:
        local_link_address = normalize_link_local_address(local_link_address)
        peer_link_address = normalize_link_local_address(peer_link_address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    peer = PeerRequest(
        user_id=user.id,
        asn=user.primary_asn,
        node_id=node.id,
        endpoint=endpoint.strip(),
        wg_public_key=wg_public_key.strip(),
        local_link_address=local_link_address,
        peer_link_address=peer_link_address,
        status="approved" if settings.auto_approve_peers else "pending",
    )
    peer.node = node
    db.add(peer)
    db.flush()
    if settings.auto_approve_peers and settings.auto_deploy_on_approval:
        deploy_peer_request(peer)
    db.commit()
    return RedirectResponse("/portal", status_code=303)


@app.get("/portal/peers/{peer_id}/config", response_class=HTMLResponse)
def peer_config(peer_id: int, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None or peer.user_id != user.id:
        raise HTTPException(status_code=404, detail="Peer request not found")
    return render(
        request,
        "config.html",
        {
            "title": f"Peer #{peer.id} config",
            "config": render_user_config(peer, peer.node, settings.local_asn or "<our-asn>"),
        },
    )


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = current_user(request, db)
    if user is None or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    peers = db.query(PeerRequest).order_by(PeerRequest.created_at.desc()).all()
    nodes = db.query(Node).order_by(Node.name).all()
    return render(request, "admin.html", {"peers": peers, "nodes": nodes})


@app.post("/admin/peers/{peer_id}/{action}")
def admin_peer_action(
    peer_id: int,
    action: str,
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    user = current_user(request, db)
    if user is None or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    if action not in {"approve", "reject", "deploy"}:
        raise HTTPException(status_code=400, detail="Unsupported action")
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer request not found")
    if action == "reject":
        peer.status = "rejected"
        peer.deploy_status = "not_deployed"
    elif action == "approve":
        peer.status = "approved"
        if settings.auto_deploy_on_approval:
            deploy_peer_request(peer)
    elif action == "deploy":
        if peer.status != "approved":
            raise HTTPException(status_code=400, detail="Only approved peers can be deployed")
        deploy_peer_request(peer)
    peer.updated_at = utcnow()
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@app.get("/admin/peers/{peer_id}/config", response_class=HTMLResponse)
def admin_peer_config(peer_id: int, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = current_user(request, db)
    if user is None or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer request not found")
    return render(
        request,
        "config.html",
        {
            "title": f"Operator config for request #{peer.id}",
            "config": render_operator_config(peer, peer.node, settings.local_asn or "<our-asn>"),
        },
    )


def deploy_peer_request(peer: PeerRequest) -> None:
    peer.deploy_status = "deploying"
    peer.deploy_output = ""
    peer.updated_at = utcnow()
    try:
        result = deploy_peer(peer, peer.node, settings)
        apply_deploy_result(peer, result)
    except Exception as exc:
        peer.deploy_status = "failed"
        peer.deploy_output = str(exc)
        peer.deployed_at = None
        peer.updated_at = utcnow()


@app.post("/lg", response_class=HTMLResponse)
async def looking_glass(
    request: Request,
    node_id: int = Form(...),
    query_type: str = Form(...),
    target: str = Form(""),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    node = db.query(Node).filter(Node.id == node_id, Node.enabled.is_(True)).one_or_none()
    if node is None:
        raise HTTPException(status_code=400, detail="Unknown node")
    result_text = ""
    ok = False
    normalized_query_type = query_type
    normalized_target = target.strip()
    try:
        normalized_query_type = validate_query_type(query_type)
        normalized_target = validate_target(normalized_query_type, target)
        result = await AgentClient().query(node, normalized_query_type, normalized_target)
        ok = bool(result.get("ok", False))
        result_text = str(result.get("output", result))
    except Exception as exc:
        result_text = f"Query failed: {exc}"
    user = current_user(request, db)
    db.add(
        LGQuery(
            user_id=user.id if user else None,
            node_id=node.id,
            query_type=normalized_query_type,
            target=normalized_target,
            ok=ok,
            result=result_text,
        )
    )
    db.commit()
    nodes = db.query(Node).filter(Node.enabled.is_(True)).order_by(Node.name).all()
    return render(
        request,
        "index.html",
        {"nodes": nodes, "lg_result": result_text, "lg_ok": ok, "last_query": normalized_query_type},
    )
