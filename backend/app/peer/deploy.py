from typing import Any

from app.config import Settings
from app.db.models import Node, PeerRequest, utcnow
from app.node_ws import NodeRequestError, request_node_sync
from app.peer.config import (
    node_effective_asn,
    peer_protocol_name,
    render_bird_peer_config,
    render_wireguard_peer_config,
)
from app.peer.validation import normalize_asn_number, normalize_wireguard_key


class PeerDeployError(Exception):
    pass


def build_deploy_payload(peer: PeerRequest, node: Node, settings: Settings) -> dict[str, Any]:
    local_asn = node_effective_asn(node, settings.local_asn)
    if not local_asn:
        raise PeerDeployError(
            "An ASN (the node's ASN or LOCAL_ASN) is required before peers can be deployed"
        )
    try:
        local_asn = normalize_asn_number(local_asn)
    except ValueError as exc:
        raise PeerDeployError(str(exc)) from exc
    if not peer.local_link_address.strip():
        raise PeerDeployError("Local peer address is required before deployment")
    if not peer.peer_link_address.strip():
        raise PeerDeployError("Remote peer address is required before deployment")
    return {
        "request_id": peer.id,
        "asn": peer.asn,
        "node": node.name,
        "protocol_name": peer_protocol_name(peer, node),
        "wireguard_config": render_wireguard_peer_config(
            peer,
            node,
            settings.wireguard_private_key_placeholder,
        ),
        "bird_config": render_bird_peer_config(peer, node, local_asn),
    }


def deploy_peer(
    peer: PeerRequest, node: Node, settings: Settings, timeout: float = 20.0
) -> dict[str, Any]:
    if not node.enabled:
        raise PeerDeployError("Node is disabled")
    payload = build_deploy_payload(peer, node, settings)
    return request_node_sync(node, "peers.deploy", payload, timeout)


def remove_peer(peer: PeerRequest, node: Node, timeout: float = 20.0) -> dict[str, Any]:
    """Ask the node to tear down a peer: bring the tunnel down and delete its config files."""
    payload = {
        "request_id": peer.id,
        "protocol_name": peer_protocol_name(peer, node),
    }
    return request_node_sync(node, "peers.remove", payload, timeout)


def fetch_node_public_key(node: Node, timeout: float = 10.0) -> str | None:
    """Fetch and validate the node's own WireGuard public key through its WSS ``pubkey`` command.

    Returns the normalized 44-char key, or ``None`` when the node is unreachable/errors or returns
    a value that is not a well-formed WireGuard key. Callers treat ``None`` as "leave the cached key
    unchanged" so a transient outage never wipes a previously fetched key.
    """
    try:
        data = request_node_sync(node, "pubkey", {}, timeout)
    except (NodeRequestError, RuntimeError, ValueError):
        return None
    key = data.get("public_key") if isinstance(data, dict) else None
    if not isinstance(key, str):
        return None
    try:
        return normalize_wireguard_key(key)
    except ValueError:
        return None


def apply_deploy_result(peer: PeerRequest, result: dict[str, Any]) -> None:
    ok = bool(result.get("ok", False))
    peer.deploy_output = str(result.get("output", result))
    if ok:
        peer.deploy_status = "deployed"
        peer.deployed_at = utcnow()
    else:
        peer.deploy_status = "failed"
        peer.deployed_at = None
    peer.updated_at = utcnow()
