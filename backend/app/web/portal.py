"""User portal: list peers, create a peer, and view a peer's generated config.

Unauthenticated requests are redirected to /login (not rejected with 403), so these routes resolve
the user inline rather than via the require_admin dependency.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session, joinedload

from app.auth.session import current_user
from app.db.models import Agent, PeerRequest
from app.db.session import get_db
from app.peer.config import peering_info, render_user_config
from app.peer.service import create_peer
from app.peer.validation import (
    DEFAULT_WIREGUARD_MTU,
    MAX_WIREGUARD_MTU,
    MIN_WIREGUARD_MTU,
    asn_link_local_address,
)
from app.web.deps import flash, query_enabled_agents, render, settings

router = APIRouter()


@router.get("/portal", response_class=HTMLResponse)
def portal(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    agents = query_enabled_agents(db).all()
    # joinedload the agent so the template's peer.agent access does not lazy-load per row (N+1).
    peers = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.agent))
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
            # Pair each peer with the "our side" details so the template can show them inline, but
            # only compute them for deployed peers (the only ones that display them).
            # 僅對已部署的 peer 計算「我方」參數,因為只有它們會顯示。
            "peers": [
                {
                    "peer": peer,
                    "peering": peering_info(peer, peer.agent)
                    if peer.deploy_status == "deployed"
                    else None,
                }
                for peer in peers
            ],
            "default_local_link_address": default_local_link_address,
            "default_peer_link_address": default_peer_link_address,
            "default_wireguard_mtu": DEFAULT_WIREGUARD_MTU,
            "wireguard_mtu_min": MIN_WIREGUARD_MTU,
            "wireguard_mtu_max": MAX_WIREGUARD_MTU,
        },
        user=user,
        active="portal",
    )


@router.post("/portal/peers")
def create_peer_request(
    request: Request,
    agent_id: int = Form(...),
    endpoint: str = Form(...),
    wg_public_key: str = Form(...),
    wg_mtu: str | None = Form(None),
    local_link_address: str = Form(...),
    peer_link_address: str = Form(...),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    agent = query_enabled_agents(db).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        flash(request, "Unknown or disabled agent.", "error")
        return RedirectResponse("/portal", status_code=303)
    try:
        create_peer(
            db,
            user=user,
            agent=agent,
            endpoint=endpoint,
            wg_public_key=wg_public_key,
            wg_mtu=wg_mtu,
            local_link_address=local_link_address,
            peer_link_address=peer_link_address,
            settings=settings,
        )
    except ValueError as exc:
        # Surface validation/duplicate errors as a flash banner instead of a raw JSON 400.
        flash(request, str(exc), "error")
        return RedirectResponse("/portal", status_code=303)
    db.commit()
    flash(request, "Peer created and deployment requested.", "success")
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
            "subtitle": f"Your generated WireGuard config for AS{peer.asn} on {peer.agent.name}.",
            "config": render_user_config(peer, peer.agent, settings.local_asn or "<our-asn>"),
            "back_url": "/portal",
        },
        user=user,
        active="portal",
    )
