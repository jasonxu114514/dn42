"""Peer lifecycle operations shared by the web routes and the Telegram bot endpoints.

Centralises the one-peer-per-Node rule, field normalisation, and deploy/teardown orchestration so
the portal, admin panel, and bot all behave identically.
"""

import logging
from ipaddress import IPv6Address, IPv6Network

from app.config import Settings
from app.db.models import Node, PeerRequest, User, utcnow
from app.peer.config import node_effective_asn
from app.peer.deploy import apply_deploy_result, deploy_peer, remove_peer
from app.peer.validation import (
    asn_link_local_address,
    is_link_local,
    normalize_dn42_asn_suffix,
    normalize_endpoint,
    normalize_tunnel_address,
    normalize_wireguard_key,
    normalize_wireguard_mtu,
)

logger = logging.getLogger("dn42.autopeer")


def deploy_peer_request(peer: PeerRequest, settings: Settings) -> None:
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


def teardown_peer_request(peer: PeerRequest) -> None:
    peer.updated_at = utcnow()
    try:
        result = remove_peer(peer, peer.node)
        if bool(result.get("ok", False)):
            peer.deploy_status = "removed"
            peer.deployed_at = None
        else:
            peer.deploy_status = "failed"
        peer.deploy_output = str(result.get("output", result))
    except Exception as exc:
        peer.deploy_status = "failed"
        peer.deploy_output = f"teardown failed: {exc}"


def find_peer_on_node(
    db, node_id: str, asn: str, *, exclude_id: str | None = None
) -> PeerRequest | None:
    """Return the existing peer for (node, asn) if any, optionally ignoring one peer id."""
    query = db.query(PeerRequest).filter(
        PeerRequest.node_id == node_id,
        PeerRequest.asn == asn,
    )
    if exclude_id is not None:
        query = query.filter(PeerRequest.id != exclude_id)
    return query.first()


def derive_peer_link_address(user_asn: str) -> str:
    """The peer's default in-tunnel address: the link-local derived from their ASN.

    Used to prefill the portal form and as the bot's automatic value. Raises ValueError when the
    ASN cannot be turned into a link-local address. 對端預設隧道位址:由其 ASN 推導的 link-local。"""
    return asn_link_local_address(user_asn)


def _derive_local_link_address(node: Node, settings: Settings, peer_link_address: str) -> str:
    """Our in-tunnel BGP address for a peer, auto-derived to share the peer's address family.

    A link-local peer → our ``fe80::<node-suffix>`` (from the node's effective ASN). A ULA peer →
    the same ``/64`` the peer chose, with our host id from the node ASN, so both ends sit on one
    subnet and BGP can establish. Returns ``""`` when no ASN is configured to derive from (the
    admin can then set our address explicitly). 我方隧道位址,自動與對端同位址族:link-local 對端→
    我方 fe80::<節點後綴>;ULA 對端→沿用對端 /64、主機位以節點 ASN 後綴,使兩端同子網。
    """
    asn = node_effective_asn(node, settings.local_asn)
    if not asn:
        return ""
    try:
        if is_link_local(peer_link_address):
            return asn_link_local_address(asn)
        suffix = normalize_dn42_asn_suffix(asn)
        peer_ip = IPv6Address(peer_link_address.split("/", 1)[0])
        net = IPv6Network((int(peer_ip), 64), strict=False)
        return str(IPv6Address(int(net.network_address) + int(suffix, 16)))
    except ValueError:
        return ""


def create_peer(
    db,
    *,
    user: User,
    node: Node,
    endpoint: str,
    wg_public_key: str,
    peer_link_address: str,
    settings: Settings,
    local_link_address: str = "",
    wg_mtu: int | str | None = None,
) -> PeerRequest:
    """Create, persist (flush), and deploy a peer for ``user`` on ``node``.

    Enforces one peer per ASN per Node and validates all fields. ``endpoint`` may be blank (the peer
    dials us). ``peer_link_address`` may be a link-local or a ULA. When ``local_link_address`` is
    omitted, our side is derived from the node to match the peer's family. Raises ValueError on a
    duplicate or invalid input. The caller commits the session.
    """
    if find_peer_on_node(db, node.id, user.primary_asn) is not None:
        raise ValueError(
            "You already have a peer on this node. Edit or delete the existing one instead."
        )
    endpoint = normalize_endpoint(endpoint)
    wg_public_key = normalize_wireguard_key(wg_public_key)
    wg_mtu = normalize_wireguard_mtu(wg_mtu)
    peer_link_address = normalize_tunnel_address(peer_link_address)
    local_link_address = (local_link_address or "").strip()
    if not local_link_address:
        local_link_address = _derive_local_link_address(node, settings, peer_link_address)
        if not local_link_address:
            raise ValueError(
                "Cannot derive our tunnel address — set the node's ASN (or LOCAL_ASN) first."
            )
    local_link_address = normalize_tunnel_address(local_link_address)
    peer = PeerRequest(
        user_id=user.id,
        asn=user.primary_asn,
        node_id=node.id,
        endpoint=endpoint,
        wg_public_key=wg_public_key,
        wg_mtu=wg_mtu,
        local_link_address=local_link_address,
        peer_link_address=peer_link_address,
        status="approved",
    )
    peer.node = node
    db.add(peer)
    db.flush()
    deploy_peer_request(peer, settings)
    return peer


def update_peer(
    db,
    *,
    peer: PeerRequest,
    node: Node,
    endpoint: str,
    wg_public_key: str,
    local_link_address: str,
    peer_link_address: str,
    status: str,
    settings: Settings,
    redeploy: bool = False,
    wg_mtu: int | str | None = None,
) -> None:
    """Update a peer's fields. Tears down a peer moved to ``disabled``; optionally redeploys an
    approved peer. Raises ValueError on a duplicate or invalid input. Caller commits.
    """
    if status not in {"approved", "disabled"}:
        raise ValueError("Unsupported peer status")
    duplicate = find_peer_on_node(db, node.id, peer.asn, exclude_id=peer.id)
    if duplicate is not None:
        raise ValueError(f"AS{peer.asn} already has another peer on this node.")
    endpoint = normalize_endpoint(endpoint)
    wg_public_key = normalize_wireguard_key(wg_public_key)
    if wg_mtu is not None:
        peer.wg_mtu = normalize_wireguard_mtu(wg_mtu)
    local_link_address = normalize_tunnel_address(local_link_address)
    peer_link_address = normalize_tunnel_address(peer_link_address)
    peer.node_id = node.id
    peer.node = node
    peer.endpoint = endpoint
    peer.wg_public_key = wg_public_key
    peer.local_link_address = local_link_address
    peer.peer_link_address = peer_link_address
    peer.status = status
    peer.updated_at = utcnow()
    if status == "disabled":
        teardown_peer_request(peer)
    elif redeploy:
        deploy_peer_request(peer, settings)


def delete_peer(db, *, peer: PeerRequest) -> None:
    """Tear the peer down on its node (best effort) and delete the row. Caller commits."""
    try:
        remove_peer(peer, peer.node)
    except Exception as exc:
        logger.warning(
            "Could not tear down peer %s on node %s before delete: %s",
            peer.id,
            peer.node.name,
            exc,
        )
    db.delete(peer)
