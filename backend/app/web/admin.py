"""Admin panel: view and manage everything — overview dashboard, nodes (PoPs), peers, users, and
the looking-glass audit log. Every route requires an admin user via ``require_admin``.

The page is split per section (``/admin``, ``/admin/nodes``, ``/admin/peers``, ``/admin/users``,
``/admin/lg-log``) so each query stays small. Browser form errors surface as flash banners +
redirect; genuine not-found stays a 404 (styled by the global handler).
"""

import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload, selectinload

from app.auth.service import unbind_telegram
from app.db.models import ASNIdentity, LGQuery, Node, PeerRequest, TelegramBinding, User
from app.db.session import get_db
from app.lg.client import NodeClient
from app.node_ws import node_runtime_context
from app.peer.config import peer_protocol_name, render_operator_config
from app.peer.deploy import fetch_node_public_key
from app.peer.service import (
    create_peer,
    delete_peer,
    deploy_peer_request,
    find_peer_on_node,
    update_peer,
)
from app.peer.validation import (
    DEFAULT_WIREGUARD_MTU,
    MAX_WIREGUARD_MTU,
    MIN_WIREGUARD_MTU,
    asn_link_local_address,
    normalize_asn_number,
    normalize_node_host,
    normalize_optional_ip,
)
from app.web.deps import Pagination, flash, render, require_admin, settings

router = APIRouter()

LG_LOG_PER_PAGE = 50


def _clean_node_fields(asn: str, dn42_ipv4: str, dn42_ipv6: str) -> tuple[str, str, str]:
    """Validate/normalise the optional per-node dn42 fields. Raises ValueError on bad input."""
    asn = asn.strip()
    if asn:
        asn = normalize_asn_number(asn)
    return (
        asn,
        normalize_optional_ip(dn42_ipv4, version=4),
        normalize_optional_ip(dn42_ipv6, version=6),
    )


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

    nodes_for_runtime = db.query(Node).order_by(Node.name).all()
    runtime = node_runtime_context(nodes_for_runtime)
    nodes_online = sum(1 for item in runtime.values() if item["online"])
    stats = {
        "nodes_total": count(Node),
        "nodes_enabled": count(Node, Node.enabled.is_(True)),
        "nodes_online": nodes_online,
        "peers_total": count(PeerRequest),
        "peers_deployed": count(PeerRequest, PeerRequest.deploy_status == "deployed"),
        "peers_failed": count(PeerRequest, PeerRequest.deploy_status == "failed"),
        "users_total": count(User),
        "users_admin": count(User, User.is_admin.is_(True)),
        "lg_total": count(LGQuery),
    }
    failed_peers = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .filter(PeerRequest.deploy_status == "failed")
        .order_by(PeerRequest.updated_at.desc())
        .limit(10)
        .all()
    )
    recent_peers = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .order_by(PeerRequest.created_at.desc())
        .limit(6)
        .all()
    )
    recent_queries = (
        db.query(LGQuery)
        .options(joinedload(LGQuery.node), joinedload(LGQuery.user))
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


@router.get("/admin/nodes", response_class=HTMLResponse)
def admin_nodes(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    nodes = db.query(Node).order_by(Node.name).all()
    return render(
        request,
        "admin/nodes.html",
        {"nodes": nodes, "node_runtime": node_runtime_context(nodes)},
        user=user,
        active="admin",
    )


@router.get("/admin/nodes/{node_id}/edit", response_class=HTMLResponse)
def admin_node_edit(
    node_id: str,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    node = db.query(Node).filter(Node.id == node_id).one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    runtime = node_runtime_context([node])[node.id]
    return render(
        request,
        "admin/node_edit.html",
        {"node": node, "runtime": runtime},
        user=user,
        active="admin",
    )


@router.get("/admin/peers", response_class=HTMLResponse)
def admin_peers(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    nodes = db.query(Node).order_by(Node.name).all()
    try:
        default_local_link_address = asn_link_local_address(settings.local_asn)
    except ValueError:
        default_local_link_address = ""
    # joinedload the node so the per-row peer.node access does not lazy-load (N+1).
    peers = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .order_by(PeerRequest.created_at.desc())
        .all()
    )
    return render(
        request,
        "admin/peers.html",
        {
            "nodes": nodes,
            "peers": peers,
            "default_local_link_address": default_local_link_address,
            "default_wireguard_mtu": DEFAULT_WIREGUARD_MTU,
            "wireguard_mtu_min": MIN_WIREGUARD_MTU,
            "wireguard_mtu_max": MAX_WIREGUARD_MTU,
        },
        user=user,
        active="admin",
    )


@router.get("/admin/peers/{peer_id}/edit", response_class=HTMLResponse)
def admin_peer_edit(
    peer_id: str,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    peer = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .filter(PeerRequest.id == peer_id)
        .one_or_none()
    )
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    nodes = db.query(Node).order_by(Node.name).all()
    return render(
        request,
        "admin/peer_edit.html",
        {
            "peer": peer,
            "nodes": nodes,
            "default_wireguard_mtu": DEFAULT_WIREGUARD_MTU,
            "wireguard_mtu_min": MIN_WIREGUARD_MTU,
            "wireguard_mtu_max": MAX_WIREGUARD_MTU,
        },
        user=user,
        active="admin",
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
        .options(joinedload(LGQuery.node), joinedload(LGQuery.user))
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


# --------------------------------------------------------------------------- nodes (POST)


@router.post("/admin/nodes")
def admin_create_node(
    request: Request,
    name: str = Form(...),
    location: str = Form(""),
    url: str = Form(...),
    asn: str = Form(""),
    dn42_ipv4: str = Form(""),
    dn42_ipv6: str = Form(""),
    enabled: str | None = Form(None),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    name = name.strip()
    if not name:
        flash(request, "Node name is required.", "error")
        return RedirectResponse("/admin/nodes", status_code=303)
    try:
        url = normalize_node_host(url)
        asn, dn42_ipv4, dn42_ipv6 = _clean_node_fields(asn, dn42_ipv4, dn42_ipv6)
    except ValueError as exc:
        flash(request, str(exc), "error")
        return RedirectResponse("/admin/nodes", status_code=303)
    if db.query(Node).filter(Node.name == name).one_or_none() is not None:
        flash(request, f"A node named '{name}' already exists.", "error")
        return RedirectResponse("/admin/nodes", status_code=303)
    node = Node(
        name=name,
        location=location.strip(),
        url=url,
        asn=asn,
        dn42_ipv4=dn42_ipv4,
        dn42_ipv6=dn42_ipv6,
        token=secrets.token_urlsafe(32),
        enabled=enabled == "on",
    )
    db.add(node)
    db.commit()
    flash(request, f"Node '{name}' created.", "success")
    return RedirectResponse("/admin/nodes", status_code=303)


@router.post("/admin/nodes/{node_id}/update")
def admin_update_node(
    node_id: str,
    request: Request,
    name: str = Form(...),
    location: str = Form(""),
    url: str = Form(...),
    asn: str = Form(""),
    dn42_ipv4: str = Form(""),
    dn42_ipv6: str = Form(""),
    enabled: str | None = Form(None),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    node = db.query(Node).filter(Node.id == node_id).one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    edit_url = f"/admin/nodes/{node_id}/edit"
    name = name.strip()
    if not name:
        flash(request, "Node name is required.", "error")
        return RedirectResponse(edit_url, status_code=303)
    try:
        url = normalize_node_host(url)
        asn, dn42_ipv4, dn42_ipv6 = _clean_node_fields(asn, dn42_ipv4, dn42_ipv6)
    except ValueError as exc:
        flash(request, str(exc), "error")
        return RedirectResponse(edit_url, status_code=303)
    existing = db.query(Node).filter(Node.name == name, Node.id != node.id).one_or_none()
    if existing is not None:
        flash(request, f"A node named '{name}' already exists.", "error")
        return RedirectResponse(edit_url, status_code=303)
    node.name = name
    node.location = location.strip()
    node.url = url
    node.asn = asn
    node.dn42_ipv4 = dn42_ipv4
    node.dn42_ipv6 = dn42_ipv6
    node.enabled = enabled == "on"
    # Re-sync the public key from the (maybe changed) URL; keep the old value if the node is down.
    fetched = fetch_node_public_key(node)
    if fetched is not None:
        node.wg_public_key = fetched
    db.commit()
    flash(request, f"Node '{name}' saved.", "success")
    return RedirectResponse(edit_url, status_code=303)


@router.post("/admin/nodes/{node_id}/refresh-pubkey")
def admin_refresh_node_pubkey(
    node_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    node = db.query(Node).filter(Node.id == node_id).one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    key = fetch_node_public_key(node)
    if key is None:
        flash(
            request,
            "Could not fetch a WireGuard public key from the node. Check WSS connectivity, "
            "node name/token, and that wireguard_public_key is set in the agent's config, "
            "then retry.",
            "error",
        )
        return RedirectResponse(f"/admin/nodes/{node_id}/edit", status_code=303)
    node.wg_public_key = key
    db.commit()
    flash(request, f"Refreshed WireGuard public key for '{node.name}'.", "success")
    return RedirectResponse(f"/admin/nodes/{node_id}/edit", status_code=303)


@router.post("/admin/nodes/{node_id}/reset-token")
def admin_reset_node_token(
    node_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    node = db.query(Node).filter(Node.id == node_id).one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    node.token = secrets.token_urlsafe(32)
    db.commit()
    flash(request, f"Issued a new API token for '{node.name}'.", "success")
    return RedirectResponse(f"/admin/nodes/{node_id}/edit", status_code=303)


@router.post("/admin/nodes/{node_id}/delete")
def admin_delete_node(
    node_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    node = db.query(Node).filter(Node.id == node_id).one_or_none()
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    if db.query(PeerRequest).filter(PeerRequest.node_id == node.id).first() is not None:
        flash(request, "Delete or move this node's peers before deleting it.", "error")
        return RedirectResponse("/admin/nodes", status_code=303)
    name = node.name
    db.delete(node)
    db.commit()
    flash(request, f"Deleted node '{name}'.", "success")
    return RedirectResponse("/admin/nodes", status_code=303)


# --------------------------------------------------------------------------- peers (POST)


@router.post("/admin/peers")
def admin_create_peer(
    request: Request,
    asn: str = Form(...),
    node_id: str = Form(...),
    endpoint: str = Form(""),
    wg_public_key: str = Form(...),
    wg_mtu: str | None = Form(None),
    local_link_address: str = Form(...),
    peer_link_address: str = Form(""),
    peer_dn42_ipv4: str = Form(""),
    peer_dn42_ipv6: str = Form(""),
    bgp_extended: str | None = Form(None),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    try:
        asn_number = normalize_asn_number(asn)
    except ValueError as exc:
        flash(request, str(exc), "error")
        return RedirectResponse("/admin/peers", status_code=303)
    node = db.query(Node).filter(Node.id == node_id).one_or_none()
    if node is None:
        flash(request, "Unknown node.", "error")
        return RedirectResponse("/admin/peers", status_code=303)
    duplicate = find_peer_on_node(db, node.id, asn_number)
    if duplicate is not None:
        flash(request, f"AS{asn_number} already has a peer on {node.name}.", "error")
        return RedirectResponse("/admin/peers", status_code=303)
    peer_user = db.query(User).filter(User.primary_asn == asn_number).one_or_none()
    if peer_user is None:
        try:
            is_admin = asn_number == normalize_asn_number(settings.local_asn)
        except ValueError:
            is_admin = False
        peer_user = User(primary_asn=asn_number, is_admin=is_admin)
        db.add(peer_user)
        db.flush()
        db.add(ASNIdentity(user_id=peer_user.id, asn=asn_number, authtype="admin-manual"))
    try:
        peer = create_peer(
            db,
            user=peer_user,
            node=node,
            endpoint=endpoint,
            wg_public_key=wg_public_key,
            wg_mtu=wg_mtu,
            local_link_address=local_link_address,
            peer_link_address=peer_link_address,
            peer_dn42_ipv4=peer_dn42_ipv4,
            peer_dn42_ipv6=peer_dn42_ipv6,
            bgp_extended=bgp_extended,
            settings=settings,
        )
    except ValueError as exc:
        flash(request, str(exc), "error")
        return RedirectResponse("/admin/peers", status_code=303)
    db.commit()
    if peer.deploy_status == "deployed":
        flash(request, f"Peer for AS{asn_number} on {node.name} created and deployed.", "success")
    else:
        flash(
            request,
            f"Peer for AS{asn_number} created, deploy failed: {peer.deploy_output[:200]}",
            "error",
        )
    return RedirectResponse("/admin/peers", status_code=303)


@router.post("/admin/peers/{peer_id}/update")
def admin_update_peer(
    peer_id: str,
    request: Request,
    node_id: str = Form(...),
    endpoint: str = Form(""),
    wg_public_key: str = Form(...),
    wg_mtu: str | None = Form(None),
    local_link_address: str = Form(...),
    peer_link_address: str = Form(""),
    peer_dn42_ipv4: str = Form(""),
    peer_dn42_ipv6: str = Form(""),
    bgp_extended: str | None = Form(None),
    status: str = Form("approved"),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    edit_url = f"/admin/peers/{peer_id}/edit"
    node = db.query(Node).filter(Node.id == node_id).one_or_none()
    if node is None:
        flash(request, "Unknown node.", "error")
        return RedirectResponse(edit_url, status_code=303)
    try:
        update_peer(
            db,
            peer=peer,
            node=node,
            endpoint=endpoint,
            wg_public_key=wg_public_key,
            wg_mtu=wg_mtu,
            local_link_address=local_link_address,
            peer_link_address=peer_link_address,
            peer_dn42_ipv4=peer_dn42_ipv4,
            peer_dn42_ipv6=peer_dn42_ipv6,
            bgp_extended=bgp_extended,
            status=status,
            settings=settings,
            redeploy=False,
        )
    except ValueError as exc:
        flash(request, str(exc), "error")
        return RedirectResponse(edit_url, status_code=303)
    db.commit()
    flash(request, "Peer saved.", "success")
    return RedirectResponse(edit_url, status_code=303)


@router.post("/admin/peers/{peer_id}/redeploy")
def admin_redeploy_peer(
    peer_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    edit_url = f"/admin/peers/{peer_id}/edit"
    if peer.status != "approved":
        flash(request, "Only approved peers can be deployed.", "error")
        return RedirectResponse(edit_url, status_code=303)
    deploy_peer_request(peer, settings)
    db.commit()
    if peer.deploy_status == "deployed":
        flash(request, "Peer redeployed.", "success")
    else:
        flash(request, f"Peer deploy failed: {peer.deploy_output[:200]}", "error")
    return RedirectResponse(edit_url, status_code=303)


@router.post("/admin/peers/{peer_id}/delete")
def admin_delete_peer(
    peer_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> RedirectResponse:
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    delete_peer(db, peer=peer)
    db.commit()
    flash(request, "Deleted peer.", "success")
    return RedirectResponse("/admin/peers", status_code=303)


@router.get("/admin/peers/{peer_id}/config", response_class=HTMLResponse)
def admin_peer_config(
    peer_id: str,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    peer = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .filter(PeerRequest.id == peer_id)
        .one_or_none()
    )
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    return render(
        request,
        "config.html",
        {
            "title": f"Operator config for AS{peer.asn}",
            "subtitle": f"WireGuard + BIRD snippets for AS{peer.asn} on {peer.node.name}.",
            "config": render_operator_config(peer, peer.node, settings.local_asn or "<our-asn>"),
            "back_url": f"/admin/peers/{peer.id}/edit",
        },
        user=user,
        active="admin",
    )


@router.get("/admin/peers/{peer_id}/status", response_class=HTMLResponse)
async def admin_peer_status(
    peer_id: str,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Show one peer's full live WireGuard + BIRD status, fetched from its node agent.

    The complete, unmodified command output — the portal/bot views condense it to key info. A dead
    or disabled node renders a notice instead of failing the page.
    """
    peer = (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .filter(PeerRequest.id == peer_id)
        .one_or_none()
    )
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    node = peer.node
    protocol_name = peer_protocol_name(peer, node)
    bird = wg = ""
    error = None
    try:
        result = await NodeClient().peer_status(node, protocol_name)
        bird = str(result.get("output", "")).strip()
        wg = str(result.get("wireguard", "")).strip()
    except Exception as exc:  # noqa: BLE001 - surface node errors as a notice, never a 500
        error = f"Could not fetch live status from {node.name}: {exc}"
    return render(
        request,
        "admin/peer_status.html",
        {
            "peer": peer,
            "node": node,
            "protocol_name": protocol_name,
            "bird": bird,
            "wg": wg,
            "error": error,
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
