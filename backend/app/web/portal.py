"""User portal: list peers, create a peer, and view a peer's generated config.

Unauthenticated requests are redirected to /login (not rejected with 403), so these routes resolve
the user inline rather than via the require_admin dependency.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.auth.session import current_user
from app.db.models import Agent, PeerRequest
from app.db.session import get_db
from app.peer.config import peering_info, render_user_config
from app.peer.service import create_peer
from app.peer.validation import asn_link_local_address
from app.web.deps import query_enabled_agents, render, settings

router = APIRouter()


@router.get("/portal", response_class=HTMLResponse)
def portal(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    agents = query_enabled_agents(db).all()
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
            "agents": agents,
            # Pair each peer with the "our side" details so the template can show them inline once
            # the peer is deployed. 把每個 peer 與「我方」參數配對,部署成功後於頁面就地顯示。
            "peers": [{"peer": peer, "peering": peering_info(peer, peer.agent)} for peer in peers],
            "default_local_link_address": default_local_link_address,
            "default_peer_link_address": default_peer_link_address,
        },
        user=user,
    )


@router.post("/portal/peers")
def create_peer_request(
    request: Request,
    agent_id: int = Form(...),
    endpoint: str = Form(...),
    wg_public_key: str = Form(...),
    local_link_address: str = Form(...),
    peer_link_address: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    agent = query_enabled_agents(db).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=400, detail="Unknown or disabled agent")
    try:
        create_peer(
            db,
            user=user,
            agent=agent,
            endpoint=endpoint,
            wg_public_key=wg_public_key,
            local_link_address=local_link_address,
            peer_link_address=peer_link_address,
            settings=settings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return RedirectResponse("/portal", status_code=303)


@router.get("/portal/peers/{peer_id}/config", response_class=HTMLResponse)
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
            "config": render_user_config(peer, peer.agent, settings.local_asn or "<our-asn>"),
        },
        user=user,
    )
