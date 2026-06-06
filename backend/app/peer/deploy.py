from typing import Any

import httpx

from app.config import Settings
from app.db.models import Node, PeerRequest, utcnow
from app.peer.config import (
    peer_protocol_name,
    render_bird_peer_config,
    render_wireguard_peer_config,
)
from app.peer.validation import normalize_asn_number


class PeerDeployError(Exception):
    pass


def build_deploy_payload(peer: PeerRequest, node: Node, settings: Settings) -> dict[str, Any]:
    local_asn = settings.local_asn.strip()
    if not local_asn:
        raise PeerDeployError("LOCAL_ASN is required before peers can be deployed")
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


def deploy_peer(peer: PeerRequest, node: Node, settings: Settings, timeout: float = 20.0) -> dict[str, Any]:
    payload = build_deploy_payload(peer, node, settings)
    headers = {"Authorization": f"Bearer {node.agent_token}"} if node.agent_token else {}
    response = httpx.post(
        f"{node.agent_url.rstrip('/')}/v1/peers/deploy",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


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
