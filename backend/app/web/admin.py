"""Admin panel: manage agents (PoPs) and peers. Every route requires an admin user via the
``require_admin`` dependency, which replaces the per-handler current-user/is-admin checks.
"""

import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.db.models import Agent, PeerRequest, User
from app.db.session import get_db
from app.peer.config import render_operator_config
from app.peer.deploy import fetch_agent_public_key
from app.peer.service import delete_peer, deploy_peer_request, update_peer
from app.web.deps import render, require_admin, settings

router = APIRouter()


@router.get("/admin", response_class=HTMLResponse)
def admin(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    agents = db.query(Agent).order_by(Agent.name).all()
    peers = db.query(PeerRequest).order_by(PeerRequest.created_at.desc()).all()
    return render(request, "admin.html", {"agents": agents, "peers": peers}, user=user)


@router.post("/admin/agents")
def admin_create_agent(
    name: str = Form(...),
    location: str = Form(""),
    url: str = Form(...),
    enabled: str | None = Form(None),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    name = name.strip()
    url = url.strip()
    if not name or not url:
        raise HTTPException(status_code=400, detail="Agent name and URL are required")
    if db.query(Agent).filter(Agent.name == name).one_or_none() is not None:
        raise HTTPException(status_code=400, detail="Agent name already exists")
    agent = Agent(
        name=name,
        location=location.strip(),
        url=url,
        token=secrets.token_urlsafe(32),
        enabled=enabled == "on",
    )
    # Best-effort fetch of this PoP's WireGuard public key. A PoP may be registered before its agent
    # is online, so a failure just leaves the key empty (refresh it later from the admin panel).
    agent.wg_public_key = fetch_agent_public_key(agent) or ""
    db.add(agent)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/agents/{agent_id}/update")
def admin_update_agent(
    agent_id: int,
    name: str = Form(...),
    location: str = Form(""),
    url: str = Form(...),
    enabled: str | None = Form(None),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    name = name.strip()
    url = url.strip()
    if not name or not url:
        raise HTTPException(status_code=400, detail="Agent name and URL are required")
    existing = db.query(Agent).filter(Agent.name == name, Agent.id != agent.id).one_or_none()
    if existing is not None:
        raise HTTPException(status_code=400, detail="Agent name already exists")
    agent.name = name
    agent.location = location.strip()
    agent.url = url
    agent.enabled = enabled == "on"
    # Re-sync the public key from the (maybe changed) URL; keep the old value if the agent is down.
    fetched = fetch_agent_public_key(agent)
    if fetched is not None:
        agent.wg_public_key = fetched
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/agents/{agent_id}/refresh-pubkey")
def admin_refresh_agent_pubkey(
    agent_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    key = fetch_agent_public_key(agent)
    if key is None:
        raise HTTPException(
            status_code=400,
            detail="Could not fetch a valid WireGuard public key from the agent. Check the agent "
            "URL/token and that wireguard_public_key is set in the agent's config, then retry.",
        )
    agent.wg_public_key = key
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/agents/{agent_id}/reset-token")
def admin_reset_agent_token(
    agent_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.token = secrets.token_urlsafe(32)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/agents/{agent_id}/delete")
def admin_delete_agent(
    agent_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if db.query(PeerRequest).filter(PeerRequest.agent_id == agent.id).first() is not None:
        raise HTTPException(
            status_code=400, detail="Delete or move peers before deleting this agent"
        )
    db.delete(agent)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/peers/{peer_id}/update")
def admin_update_peer(
    peer_id: int,
    agent_id: int = Form(...),
    endpoint: str = Form(...),
    wg_public_key: str = Form(...),
    local_link_address: str = Form(...),
    peer_link_address: str = Form(...),
    status: str = Form("approved"),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=400, detail="Unknown agent")
    try:
        update_peer(
            db,
            peer=peer,
            agent=agent,
            endpoint=endpoint,
            wg_public_key=wg_public_key,
            local_link_address=local_link_address,
            peer_link_address=peer_link_address,
            status=status,
            settings=settings,
            redeploy=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/peers/{peer_id}/redeploy")
def admin_redeploy_peer(
    peer_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    if peer.status != "approved":
        raise HTTPException(status_code=400, detail="Only approved peers can be deployed")
    deploy_peer_request(peer, settings)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/peers/{peer_id}/delete")
def admin_delete_peer(
    peer_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    delete_peer(db, peer=peer)
    db.commit()
    return RedirectResponse("/admin", status_code=303)


@router.get("/admin/peers/{peer_id}/config", response_class=HTMLResponse)
def admin_peer_config(
    peer_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    return render(
        request,
        "config.html",
        {
            "title": f"Operator config for peer #{peer.id}",
            "config": render_operator_config(peer, peer.agent, settings.local_asn or "<our-asn>"),
        },
        user=user,
    )
