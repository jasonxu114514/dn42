from typing import Any

import httpx

from app.config import Settings
from app.db.models import Agent, PeerRequest, utcnow
from app.peer.config import (
    peer_protocol_name,
    render_bird_peer_config,
    render_wireguard_peer_config,
)
from app.peer.validation import normalize_asn_number, normalize_wireguard_key


class PeerDeployError(Exception):
    pass


def build_deploy_payload(peer: PeerRequest, agent: Agent, settings: Settings) -> dict[str, Any]:
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
        "agent": agent.name,
        "protocol_name": peer_protocol_name(peer, agent),
        "wireguard_config": render_wireguard_peer_config(
            peer,
            agent,
            settings.wireguard_private_key_placeholder,
        ),
        "bird_config": render_bird_peer_config(peer, agent, local_asn),
    }


def deploy_peer(
    peer: PeerRequest, agent: Agent, settings: Settings, timeout: float = 20.0
) -> dict[str, Any]:
    if not agent.enabled:
        raise PeerDeployError("Agent is disabled")
    payload = build_deploy_payload(peer, agent, settings)
    headers = {"Authorization": f"Bearer {agent.token}"} if agent.token else {}
    response = httpx.post(
        f"{agent.url.rstrip('/')}/v1/peers/deploy",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def remove_peer(peer: PeerRequest, agent: Agent, timeout: float = 20.0) -> dict[str, Any]:
    """Ask the agent to tear down a peer: bring the tunnel down and delete its config files."""
    headers = {"Authorization": f"Bearer {agent.token}"} if agent.token else {}
    payload = {
        "request_id": peer.id,
        "protocol_name": peer_protocol_name(peer, agent),
    }
    response = httpx.post(
        f"{agent.url.rstrip('/')}/v1/peers/remove",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def fetch_agent_public_key(agent: Agent, timeout: float = 10.0) -> str | None:
    """Fetch and validate the agent's own WireGuard public key from its ``GET /v1/pubkey`` endpoint.

    Returns the normalized 44-char key, or ``None`` when the agent is unreachable/errors or returns
    a value that is not a well-formed WireGuard key. Callers treat ``None`` as "leave the cached key
    unchanged" so a transient outage never wipes a previously fetched key.
    """
    headers = {"Authorization": f"Bearer {agent.token}"} if agent.token else {}
    try:
        response = httpx.get(
            f"{agent.url.rstrip('/')}/v1/pubkey",
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError):
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
