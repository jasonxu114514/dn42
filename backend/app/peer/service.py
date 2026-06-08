"""Peer lifecycle operations shared by the web routes and the Telegram bot endpoints."""

import logging
from dataclasses import dataclass
from ipaddress import IPv6Address, IPv6Network

from app.config import Settings
from app.db.models import Node, PeerRequest, User, utcnow
from app.peer.config import node_effective_asn, peering_info
from app.peer.deploy import apply_deploy_result, deploy_peer, remove_peer
from app.peer.validation import (
    asn_link_local_address,
    is_link_local,
    normalize_dn42_asn_suffix,
    normalize_endpoint,
    normalize_optional_ip,
    normalize_tunnel_address,
    normalize_wireguard_key,
    normalize_wireguard_mtu,
)

logger = logging.getLogger("dn42.autopeer")


@dataclass(frozen=True)
class NormalizedPeerInput:
    endpoint: str
    wg_public_key: str
    wg_mtu: int
    local_link_address: str
    peer_link_address: str
    peer_dn42_ipv4: str
    peer_dn42_ipv6: str
    bgp_extended: bool


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
    """Default peer BGP/link-local address derived from the peer ASN."""
    return asn_link_local_address(user_asn)


def normalize_bgp_extended(value: bool | str | None = True) -> bool:
    """Normalise checkbox/API values for the BGP extension switch."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    cleaned = str(value).strip().lower()
    if cleaned in {"1", "true", "yes", "on", "enabled"}:
        return True
    if cleaned in {"0", "false", "no", "off", "disabled", ""}:
        return False
    raise ValueError("BGP extension switch must be on or off")


def _derive_local_link_address(node: Node, settings: Settings, peer_link_address: str) -> str:
    """Derive our BGP address to match a link-local or ULA peer address."""
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


def normalize_peer_input(
    *,
    peer_asn: str,
    node: Node,
    endpoint: str,
    wg_public_key: str,
    settings: Settings,
    peer_link_address: str = "",
    peer_dn42_ipv4: str = "",
    peer_dn42_ipv6: str = "",
    local_link_address: str = "",
    wg_mtu: int | str | None = None,
    bgp_extended: bool | str | None = True,
) -> NormalizedPeerInput:
    """Validate all peer fields and derive missing tunnel addresses.

    The user must provide at least one visible address: DN42 IPv4, DN42 IPv6, or link-local/BGP.
    Deployment still needs a BGP neighbor, so a blank link-local field falls back to the old
    ASN-derived default after this requirement is satisfied.
    """
    endpoint = normalize_endpoint(endpoint)
    wg_public_key = normalize_wireguard_key(wg_public_key)
    wg_mtu = normalize_wireguard_mtu(wg_mtu)
    peer_dn42_ipv4 = normalize_optional_ip(peer_dn42_ipv4, version=4)
    peer_dn42_ipv6 = normalize_optional_ip(peer_dn42_ipv6, version=6)

    peer_link_address = (peer_link_address or "").strip()
    if peer_link_address:
        peer_link_address = normalize_tunnel_address(peer_link_address)
    if not any([peer_dn42_ipv4, peer_dn42_ipv6, peer_link_address]):
        raise ValueError(
            "Enter at least one peer address: DN42 IPv4, DN42 IPv6, or link-local."
        )
    if not peer_link_address:
        if peer_dn42_ipv6:
            try:
                peer_link_address = normalize_tunnel_address(peer_dn42_ipv6)
            except ValueError:
                peer_link_address = ""
        if not peer_link_address:
            peer_link_address = derive_peer_link_address(peer_asn)

    local_link_address = (local_link_address or "").strip()
    if not local_link_address:
        local_link_address = _derive_local_link_address(node, settings, peer_link_address)
        if not local_link_address:
            raise ValueError(
                "Cannot derive our tunnel address - set the node's ASN (or LOCAL_ASN) first."
            )
    local_link_address = normalize_tunnel_address(local_link_address)

    return NormalizedPeerInput(
        endpoint=endpoint,
        wg_public_key=wg_public_key,
        wg_mtu=wg_mtu,
        local_link_address=local_link_address,
        peer_link_address=peer_link_address,
        peer_dn42_ipv4=peer_dn42_ipv4,
        peer_dn42_ipv6=peer_dn42_ipv6,
        bgp_extended=normalize_bgp_extended(bgp_extended),
    )


def preview_peer(
    *,
    user: User,
    node: Node,
    endpoint: str,
    wg_public_key: str,
    settings: Settings,
    peer_link_address: str = "",
    peer_dn42_ipv4: str = "",
    peer_dn42_ipv6: str = "",
    local_link_address: str = "",
    wg_mtu: int | str | None = None,
    bgp_extended: bool | str | None = True,
) -> dict[str, object]:
    """Return normalized peer values and our-side details without deploying."""
    values = normalize_peer_input(
        peer_asn=user.primary_asn,
        node=node,
        endpoint=endpoint,
        wg_public_key=wg_public_key,
        settings=settings,
        peer_link_address=peer_link_address,
        peer_dn42_ipv4=peer_dn42_ipv4,
        peer_dn42_ipv6=peer_dn42_ipv6,
        local_link_address=local_link_address,
        wg_mtu=wg_mtu,
        bgp_extended=bgp_extended,
    )
    peer = PeerRequest(
        user_id=user.id,
        asn=user.primary_asn,
        node_id=node.id,
        endpoint=values.endpoint,
        wg_public_key=values.wg_public_key,
        wg_mtu=values.wg_mtu,
        local_link_address=values.local_link_address,
        peer_link_address=values.peer_link_address,
        peer_dn42_ipv4=values.peer_dn42_ipv4,
        peer_dn42_ipv6=values.peer_dn42_ipv6,
        bgp_extended=values.bgp_extended,
        status="approved",
    )
    peer.node = node
    local_asn = node_effective_asn(node, settings.local_asn) or "<our-asn>"
    return {"values": values, "peering": peering_info(peer, node, local_asn)}


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
    peer_dn42_ipv4: str = "",
    peer_dn42_ipv6: str = "",
    bgp_extended: bool | str | None = True,
    wg_mtu: int | str | None = None,
) -> PeerRequest:
    """Create, persist, and deploy a peer for ``user`` on ``node``."""
    if find_peer_on_node(db, node.id, user.primary_asn) is not None:
        raise ValueError(
            "You already have a peer on this node. Edit or delete the existing one instead."
        )
    values = normalize_peer_input(
        peer_asn=user.primary_asn,
        node=node,
        endpoint=endpoint,
        wg_public_key=wg_public_key,
        wg_mtu=wg_mtu,
        peer_link_address=peer_link_address,
        peer_dn42_ipv4=peer_dn42_ipv4,
        peer_dn42_ipv6=peer_dn42_ipv6,
        local_link_address=local_link_address,
        bgp_extended=bgp_extended,
        settings=settings,
    )
    peer = PeerRequest(
        user_id=user.id,
        asn=user.primary_asn,
        node_id=node.id,
        endpoint=values.endpoint,
        wg_public_key=values.wg_public_key,
        wg_mtu=values.wg_mtu,
        local_link_address=values.local_link_address,
        peer_link_address=values.peer_link_address,
        peer_dn42_ipv4=values.peer_dn42_ipv4,
        peer_dn42_ipv6=values.peer_dn42_ipv6,
        bgp_extended=values.bgp_extended,
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
    peer_dn42_ipv4: str = "",
    peer_dn42_ipv6: str = "",
    bgp_extended: bool | str | None = True,
) -> None:
    """Update a peer's fields and optionally redeploy an approved peer."""
    if status not in {"approved", "disabled"}:
        raise ValueError("Unsupported peer status")
    duplicate = find_peer_on_node(db, node.id, peer.asn, exclude_id=peer.id)
    if duplicate is not None:
        raise ValueError(f"AS{peer.asn} already has another peer on this node.")
    values = normalize_peer_input(
        peer_asn=peer.asn,
        node=node,
        endpoint=endpoint,
        wg_public_key=wg_public_key,
        wg_mtu=wg_mtu if wg_mtu is not None else peer.wg_mtu,
        local_link_address=local_link_address,
        peer_link_address=peer_link_address,
        peer_dn42_ipv4=peer_dn42_ipv4,
        peer_dn42_ipv6=peer_dn42_ipv6,
        bgp_extended=bgp_extended,
        settings=settings,
    )
    peer.node_id = node.id
    peer.node = node
    peer.endpoint = values.endpoint
    peer.wg_public_key = values.wg_public_key
    peer.wg_mtu = values.wg_mtu
    peer.local_link_address = values.local_link_address
    peer.peer_link_address = values.peer_link_address
    peer.peer_dn42_ipv4 = values.peer_dn42_ipv4
    peer.peer_dn42_ipv6 = values.peer_dn42_ipv6
    peer.bgp_extended = values.bgp_extended
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
