from typing import Any

from app.agent_ws import AgentRequestError, request_agent_sync
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
    return request_agent_sync(agent, "peers.deploy", payload, timeout)


def remove_peer(peer: PeerRequest, agent: Agent, timeout: float = 20.0) -> dict[str, Any]:
    """Ask the agent to tear down a peer: bring the tunnel down and delete its config files."""
    payload = {
        "request_id": peer.id,
        "protocol_name": peer_protocol_name(peer, agent),
    }
    return request_agent_sync(agent, "peers.remove", payload, timeout)


def fetch_agent_public_key(agent: Agent, timeout: float = 10.0) -> str | None:
    """Fetch and validate the agent's own WireGuard public key through its WSS ``pubkey`` command.

    Returns the normalized 44-char key, or ``None`` when the agent is unreachable/errors or returns
    a value that is not a well-formed WireGuard key. Callers treat ``None`` as "leave the cached key
    unchanged" so a transient outage never wipes a previously fetched key.
    """
    try:
        data = request_agent_sync(agent, "pubkey", {}, timeout)
    except (AgentRequestError, RuntimeError, ValueError):
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
