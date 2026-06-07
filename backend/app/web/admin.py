"""Admin panel: view and manage everything — overview dashboard, agents (PoPs), peers, users, and
the looking-glass audit log. Every route requires an admin user via ``require_admin``.

The page is split per section (``/admin``, ``/admin/agents``, ``/admin/peers``, ``/admin/users``,
``/admin/lg-log``) so each query stays small. Browser form errors surface as flash banners +
redirect; genuine not-found stays a 404 (styled by the global handler).
"""

import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload, selectinload

from app.auth.service import unbind_telegram
from app.db.models import Agent, LGQuery, PeerRequest, TelegramBinding, User
from app.db.session import get_db
from app.peer.config import render_operator_config
from app.peer.deploy import fetch_agent_public_key
from app.peer.service import delete_peer, deploy_peer_request, update_peer
from app.web.deps import Pagination, flash, render, require_admin, settings

router = APIRouter()

LG_LOG_PER_PAGE = 50


# --------------------------------------------------------------------------- pages (GET)


@router.get("/admin", response_class=HTMLResponse)
def admin_overview(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    def count(model, *filters) -> int:
        query = db.query(func.count(model.id))
        for f in filters:
            query = query.filter(f)
        return query.scalar() or 0

    stats = {
        "agents_total": count(Agent),
        "agents_enabled": count(Agent, Agent.enabled.is_(True)),
        "peers_total": count(PeerRequest),
        "peers_deployed": count(PeerRequest, PeerRequest.deploy_status == "deployed"),
        "peers_failed": count(PeerRequest, PeerRequest.deploy_status == "failed"),
        "users_total": count(User),
        "users_admin": count(User, User.is_admin.is_(True)),
        "lg_total": count(LGQuery),
    }
    failed_peers = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.agent))
        .filter(PeerRequest.deploy_status == "failed")
        .order_by(PeerRequest.updated_at.desc())
        .limit(10)
        .all()
    )
    recent_peers = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.agent))
        .order_by(PeerRequest.created_at.desc())
        .limit(6)
        .all()
    )
    recent_queries = (
        db.query(LGQuery)
        .options(joinedload(LGQuery.agent), joinedload(LGQuery.user))
        .order_by(LGQuery.created_at.desc())
        .limit(8)
        .all()
    )
    return render(
        request,
        "admin/overview.html",
        {
            "stats": stats,
            "failed_peers": failed_peers,
            "recent_peers": recent_peers,
            "recent_queries": recent_queries,
        },
        user=user,
        active="admin",
    )


@router.get("/admin/agents", response_class=HTMLResponse)
def admin_agents(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    agents = db.query(Agent).order_by(Agent.name).all()
    return render(request, "admin/agents.html", {"agents": agents}, user=user, active="admin")


@router.get("/admin/peers", response_class=HTMLResponse)
def admin_peers(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    agents = db.query(Agent).order_by(Agent.name).all()
    # joinedload the agent so the per-row peer.agent access does not lazy-load (N+1).
    peers = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.agent))
        .order_by(PeerRequest.created_at.desc())
        .all()
    )
    return render(
        request, "admin/peers.html", {"agents": agents, "peers": peers}, user=user, active="admin"
    )


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    # selectinload bindings + one grouped peer-count query → no per-user lazy loads.
    users = (
        db.query(User)
        .options(selectinload(User.telegram_bindings))
        .order_by(User.primary_asn)
        .all()
    )
    peer_counts = dict(
        db.query(PeerRequest.user_id, func.count(PeerRequest.id))
        .group_by(PeerRequest.user_id)
        .all()
    )
    return render(
        request,
        "admin/users.html",
        {"users": users, "peer_counts": peer_counts},
        user=user,
        active="admin",
    )


@router.get("/admin/lg-log", response_class=HTMLResponse)
def admin_lg_log(
    request: Request,
    page: int = 1,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    total = db.query(func.count(LGQuery.id)).scalar() or 0
    pg = Pagination(page=page, per_page=LG_LOG_PER_PAGE, total=total)
    queries = (
        db.query(LGQuery)
        .options(joinedload(LGQuery.agent), joinedload(LGQuery.user))
        .order_by(LGQuery.created_at.desc())
        .limit(pg.per_page)
        .offset(pg.offset)
        .all()
    )
    return render(
        request,
        "admin/lg_log.html",
        {"queries": queries, "pg": pg},
        user=user,
        active="admin",
    )


# --------------------------------------------------------------------------- agents (POST)


@router.post("/admin/agents")
def admin_create_agent(
    request: Request,
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
        flash(request, "Agent name and URL are required.", "error")
        return RedirectResponse("/admin/agents", status_code=303)
    if db.query(Agent).filter(Agent.name == name).one_or_none() is not None:
        flash(request, f"An agent named '{name}' already exists.", "error")
        return RedirectResponse("/admin/agents", status_code=303)
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
    flash(request, f"Agent '{name}' created.", "success")
    return RedirectResponse("/admin/agents", status_code=303)


@router.post("/admin/agents/{agent_id}/update")
def admin_update_agent(
    agent_id: int,
    request: Request,
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
        flash(request, "Agent name and URL are required.", "error")
        return RedirectResponse("/admin/agents", status_code=303)
    existing = db.query(Agent).filter(Agent.name == name, Agent.id != agent.id).one_or_none()
    if existing is not None:
        flash(request, f"An agent named '{name}' already exists.", "error")
        return RedirectResponse("/admin/agents", status_code=303)
    agent.name = name
    agent.location = location.strip()
    agent.url = url
    agent.enabled = enabled == "on"
    # Re-sync the public key from the (maybe changed) URL; keep the old value if the agent is down.
    fetched = fetch_agent_public_key(agent)
    if fetched is not None:
        agent.wg_public_key = fetched
    db.commit()
    flash(request, f"Agent '{name}' saved.", "success")
    return RedirectResponse("/admin/agents", status_code=303)


@router.post("/admin/agents/{agent_id}/refresh-pubkey")
def admin_refresh_agent_pubkey(
    agent_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    key = fetch_agent_public_key(agent)
    if key is None:
        flash(
            request,
            "Could not fetch a WireGuard public key from the agent. Check the agent URL/token and "
            "that wireguard_public_key is set in the agent's config, then retry.",
            "error",
        )
        return RedirectResponse("/admin/agents", status_code=303)
    agent.wg_public_key = key
    db.commit()
    flash(request, f"Refreshed WireGuard public key for '{agent.name}'.", "success")
    return RedirectResponse("/admin/agents", status_code=303)


@router.post("/admin/agents/{agent_id}/reset-token")
def admin_reset_agent_token(
    agent_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.token = secrets.token_urlsafe(32)
    db.commit()
    flash(request, f"Issued a new API token for '{agent.name}'.", "success")
    return RedirectResponse("/admin/agents", status_code=303)


@router.post("/admin/agents/{agent_id}/delete")
def admin_delete_agent(
    agent_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if db.query(PeerRequest).filter(PeerRequest.agent_id == agent.id).first() is not None:
        flash(request, "Delete or move this PoP's peers before deleting it.", "error")
        return RedirectResponse("/admin/agents", status_code=303)
    name = agent.name
    db.delete(agent)
    db.commit()
    flash(request, f"Deleted agent '{name}'.", "success")
    return RedirectResponse("/admin/agents", status_code=303)


# --------------------------------------------------------------------------- peers (POST)


@router.post("/admin/peers/{peer_id}/update")
def admin_update_peer(
    peer_id: int,
    request: Request,
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
        flash(request, "Unknown agent.", "error")
        return RedirectResponse("/admin/peers", status_code=303)
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
        flash(request, str(exc), "error")
        return RedirectResponse("/admin/peers", status_code=303)
    db.commit()
    flash(request, f"Peer #{peer.id} saved.", "success")
    return RedirectResponse("/admin/peers", status_code=303)


@router.post("/admin/peers/{peer_id}/redeploy")
def admin_redeploy_peer(
    peer_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    if peer.status != "approved":
        flash(request, "Only approved peers can be deployed.", "error")
        return RedirectResponse("/admin/peers", status_code=303)
    deploy_peer_request(peer, settings)
    db.commit()
    if peer.deploy_status == "deployed":
        flash(request, f"Peer #{peer.id} redeployed.", "success")
    else:
        flash(request, f"Peer #{peer.id} deploy failed: {peer.deploy_output[:200]}", "error")
    return RedirectResponse("/admin/peers", status_code=303)


@router.post("/admin/peers/{peer_id}/delete")
def admin_delete_peer(
    peer_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    delete_peer(db, peer=peer)
    db.commit()
    flash(request, f"Deleted peer #{peer_id}.", "success")
    return RedirectResponse("/admin/peers", status_code=303)


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
            "subtitle": f"WireGuard + BIRD snippets for AS{peer.asn} on {peer.agent.name}.",
            "config": render_operator_config(peer, peer.agent, settings.local_asn or "<our-asn>"),
            "back_url": "/admin/peers",
        },
        user=user,
        active="admin",
    )


# --------------------------------------------------------------------------- users (POST)


@router.post("/admin/users/{user_id}/toggle-admin")
def admin_toggle_user_admin(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> RedirectResponse:
    if user_id == admin.id:
        # Guard against self-lockout. (Admin is also re-derived from LOCAL_ASN on each login.)
        flash(request, "You can't change your own admin status.", "error")
        return RedirectResponse("/admin/users", status_code=303)
    target = db.query(User).filter(User.id == user_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    target.is_admin = not target.is_admin
    db.commit()
    state = "an admin" if target.is_admin else "a regular user"
    flash(request, f"AS{target.primary_asn} is now {state}.", "success")
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/admin/users/{user_id}/unlink-telegram")
def admin_unlink_telegram(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    target = db.query(User).filter(User.id == user_id).one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    bindings = db.query(TelegramBinding).filter(TelegramBinding.user_id == user_id).all()
    if not bindings:
        flash(request, "That user has no linked Telegram account.", "info")
        return RedirectResponse("/admin/users", status_code=303)
    for binding in bindings:
        unbind_telegram(db, binding.telegram_user_id)
    flash(request, f"Unlinked Telegram from AS{target.primary_asn}.", "success")
    return RedirectResponse("/admin/users", status_code=303)
