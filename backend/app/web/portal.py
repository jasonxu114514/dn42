"""User portal: list your peers, view a peer's detail + live status, create a peer, delete a peer.

Unauthenticated requests are redirected to /login (not rejected with 403), so these routes resolve
the user inline rather than via the require_admin dependency.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.auth.session import current_user
from app.db.session import get_db
from app.lg.client import NodeClient
from app.lg.summary import summarize_peer_bird, summarize_wireguard
from app.peer.config import (
    node_effective_asn,
    peer_protocol_name,
    peering_info,
    render_user_config,
)
from app.peer.queries import enabled_node_by_id, owned_peer_with_node, peers_for_user_with_nodes
from app.peer.service import create_peer, delete_peer, derive_peer_link_address, preview_peer
from app.peer.validation import (
    DEFAULT_WIREGUARD_MTU,
    MAX_WIREGUARD_MTU,
    MIN_WIREGUARD_MTU,
)
from app.web.deps import flash, query_enabled_nodes, render, settings

router = APIRouter()


@router.get("/portal", response_class=HTMLResponse)
def portal(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    """Manage Peers: an overview of the user's peers, each linking to its detail page."""
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    peers = peers_for_user_with_nodes(db, user.id)
    return render(
        request,
        "portal.html",
        {"peers": peers, "peer_count": len(peers)},
        user=user,
        active="portal",
    )


@router.get("/portal/new", response_class=HTMLResponse)
def portal_new(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    """New Peer form: choose a node, paste a key/endpoint, pick a tunnel IP (default link-local)."""
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    nodes = query_enabled_nodes(db).all()
    try:
        default_peer_address = derive_peer_link_address(user.primary_asn)
    except ValueError:
        default_peer_address = ""
    return render(
        request,
        "portal_new.html",
        {
            "nodes": nodes,
            "default_peer_address": default_peer_address,
            "default_wireguard_mtu": DEFAULT_WIREGUARD_MTU,
            "wireguard_mtu_min": MIN_WIREGUARD_MTU,
            "wireguard_mtu_max": MAX_WIREGUARD_MTU,
        },
        user=user,
        active="new",
    )


@router.post("/portal/peers")
def create_peer_request(
    request: Request,
    node_id: str = Form(...),
    wg_public_key: str = Form(...),
    endpoint: str = Form(""),
    peer_dn42_ipv4: str = Form(""),
    peer_dn42_ipv6: str = Form(""),
    peer_link_address: str = Form(""),
    wg_mtu: str | None = Form(None),
    bgp_extended: str | None = Form(None),
    db: Session = Depends(get_db),
) -> RedirectResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    node = enabled_node_by_id(db, node_id)
    if node is None:
        flash(request, "Unknown or disabled node.", "error")
        return RedirectResponse("/portal/new", status_code=303)
    try:
        create_peer(
            db,
            user=user,
            node=node,
            endpoint=endpoint,
            wg_public_key=wg_public_key,
            wg_mtu=wg_mtu,
            peer_dn42_ipv4=peer_dn42_ipv4,
            peer_dn42_ipv6=peer_dn42_ipv6,
            peer_link_address=peer_link_address,
            bgp_extended=bgp_extended,
            settings=settings,
        )
    except ValueError as exc:
        # Surface validation/duplicate errors as a flash banner instead of a raw JSON 400.
        flash(request, str(exc), "error")
        return RedirectResponse("/portal/new", status_code=303)
    flash(request, "Peer created and deployment requested.", "success")
    return RedirectResponse("/portal", status_code=303)


@router.post("/portal/peers/confirm", response_class=HTMLResponse, response_model=None)
def confirm_peer_request(
    request: Request,
    node_id: str = Form(...),
    wg_public_key: str = Form(...),
    endpoint: str = Form(""),
    peer_dn42_ipv4: str = Form(""),
    peer_dn42_ipv6: str = Form(""),
    peer_link_address: str = Form(""),
    wg_mtu: str | None = Form(None),
    bgp_extended: str | None = Form(None),
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    node = enabled_node_by_id(db, node_id)
    if node is None:
        flash(request, "Unknown or disabled node.", "error")
        return RedirectResponse("/portal/new", status_code=303)
    try:
        preview = preview_peer(
            user=user,
            node=node,
            endpoint=endpoint,
            wg_public_key=wg_public_key,
            wg_mtu=wg_mtu,
            peer_dn42_ipv4=peer_dn42_ipv4,
            peer_dn42_ipv6=peer_dn42_ipv6,
            peer_link_address=peer_link_address,
            bgp_extended=bgp_extended,
            settings=settings,
        )
    except ValueError as exc:
        flash(request, str(exc), "error")
        return RedirectResponse("/portal/new", status_code=303)
    return render(
        request,
        "portal_confirm.html",
        {
            "node": node,
            "values": preview["values"],
            "peering": preview["peering"],
        },
        user=user,
        active="new",
    )


@router.get("/portal/peers/{peer_id}", response_class=HTMLResponse)
async def peer_detail(
    peer_id: str, request: Request, db: Session = Depends(get_db)
) -> HTMLResponse:
    """One peer's detail: ids, our-side endpoint/key (copyable), node addressing, live status."""
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    peer = owned_peer_with_node(db, user.id, peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    node = peer.node
    # Live WireGuard + BGP session status, condensed; degrade to a notice if the node is down.
    wg_status = bgp_status = None
    status_error = None
    try:
        result = await NodeClient().peer_status(node, peer_protocol_name(peer, node))
        bgp_status = summarize_peer_bird(str(result.get("output", "")))
        wg_status = summarize_wireguard(str(result.get("wireguard", "")))
    except Exception as exc:  # noqa: BLE001 - a dead node renders a notice, never a 500
        status_error = f"Live status unavailable: {exc}"
    return render(
        request,
        "peer_detail.html",
        {
            "peer": peer,
            "node": node,
            "peering": peering_info(
                peer, node, node_effective_asn(node, settings.local_asn) or "<our-asn>"
            ),
            "node_asn": node_effective_asn(node, settings.local_asn),
            "enabled": peer.status == "approved",
            "wg_status": wg_status,
            "bgp_status": bgp_status,
            "status_error": status_error,
        },
        user=user,
        active="portal",
    )


@router.post("/portal/peers/{peer_id}/delete")
def portal_delete_peer(
    peer_id: str, request: Request, db: Session = Depends(get_db)
) -> RedirectResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    peer = owned_peer_with_node(db, user.id, peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    delete_peer(db, peer=peer)
    flash(request, "Peer deleted and torn down.", "success")
    return RedirectResponse("/portal", status_code=303)


@router.get("/portal/peers/{peer_id}/config", response_class=HTMLResponse)
def peer_config(peer_id: str, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user = current_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    peer = owned_peer_with_node(db, user.id, peer_id)
    if peer is None:
        raise HTTPException(status_code=404, detail="Peer not found")
    node = peer.node
    return render(
        request,
        "config.html",
        {
            "title": "Your peer config",
            "subtitle": f"Your generated WireGuard config for AS{peer.asn} on {node.name}.",
            "config": render_user_config(
                peer, node, node_effective_asn(node, settings.local_asn) or "<our-asn>"
            ),
            "back_url": f"/portal/peers/{peer.id}",
        },
        user=user,
        active="portal",
    )
