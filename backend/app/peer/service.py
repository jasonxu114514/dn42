"""Peer lifecycle operations shared by the web routes and the Telegram bot endpoints.

Centralises the one-peer-per-PoP rule, field normalisation, and deploy/teardown orchestration so
the portal, admin panel, and bot all behave identically.
"""

import logging

from app.config import Settings
from app.db.models import Agent, PeerRequest, User, utcnow
from app.peer.deploy import apply_deploy_result, deploy_peer, remove_peer
from app.peer.validation import (
    asn_link_local_address,
    normalize_endpoint,
    normalize_link_local_address,
    normalize_wireguard_key,
)

logger = logging.getLogger("dn42.autopeer")


def deploy_peer_request(peer: PeerRequest, settings: Settings) -> None:
    peer.deploy_status = "deploying"
    peer.deploy_output = ""
    peer.updated_at = utcnow()
    try:
        result = deploy_peer(peer, peer.agent, settings)
        apply_deploy_result(peer, result)
    except Exception as exc:
        peer.deploy_status = "failed"
        peer.deploy_output = str(exc)
        peer.deployed_at = None
        peer.updated_at = utcnow()


def teardown_peer_request(peer: PeerRequest) -> None:
    peer.updated_at = utcnow()
    try:
        result = remove_peer(peer, peer.agent)
        if bool(result.get("ok", False)):
            peer.deploy_status = "removed"
            peer.deployed_at = None
        else:
            peer.deploy_status = "failed"
        peer.deploy_output = str(result.get("output", result))
    except Exception as exc:
        peer.deploy_status = "failed"
        peer.deploy_output = f"teardown failed: {exc}"


def find_peer_on_pop(db, agent_id: int, asn: str, *, exclude_id: int | None = None) -> PeerRequest | None:
    """Return the existing peer for (agent, asn) if any, optionally ignoring one peer id."""
    query = db.query(PeerRequest).filter(
        PeerRequest.agent_id == agent_id,
        PeerRequest.asn == asn,
    )
    if exclude_id is not None:
        query = query.filter(PeerRequest.id != exclude_id)
    return query.first()


def derive_link_addresses(user_asn: str, local_asn: str) -> tuple[str, str]:
    """Auto-derive (local_link_address, peer_link_address) from ASNs for bot-created peers.

    Mirrors the link-local defaults the web portal prefills. Raises ValueError when an ASN cannot
    be turned into a link-local address (e.g. LOCAL_ASN is unset).
    """
    return asn_link_local_address(local_asn), asn_link_local_address(user_asn)


def create_peer(
    db,
    *,
    user: User,
    agent: Agent,
    endpoint: str,
    wg_public_key: str,
    local_link_address: str,
    peer_link_address: str,
    settings: Settings,
) -> PeerRequest:
    """Create, persist (flush), and deploy a peer for ``user`` on ``agent``.

    Enforces one peer per ASN per PoP and validates all user-supplied fields. Raises ValueError on
    a duplicate or invalid input. The caller is responsible for committing the session.
    """
    if find_peer_on_pop(db, agent.id, user.primary_asn) is not None:
        raise ValueError("You already have a peer on this PoP. Edit or delete the existing one instead.")
    endpoint = normalize_endpoint(endpoint)
    wg_public_key = normalize_wireguard_key(wg_public_key)
    local_link_address = normalize_link_local_address(local_link_address)
    peer_link_address = normalize_link_local_address(peer_link_address)
    peer = PeerRequest(
        user_id=user.id,
        asn=user.primary_asn,
        agent_id=agent.id,
        endpoint=endpoint,
        wg_public_key=wg_public_key,
        local_link_address=local_link_address,
        peer_link_address=peer_link_address,
        status="approved",
    )
    peer.agent = agent
    db.add(peer)
    db.flush()
    deploy_peer_request(peer, settings)
    return peer


def update_peer(
    db,
    *,
    peer: PeerRequest,
    agent: Agent,
    endpoint: str,
    wg_public_key: str,
    local_link_address: str,
    peer_link_address: str,
    status: str,
    settings: Settings,
    redeploy: bool = False,
) -> None:
    """Update a peer's fields. Tears down a peer moved to ``disabled``; optionally redeploys an
    approved peer. Raises ValueError on a duplicate or invalid input. Caller commits.
    """
    if status not in {"approved", "disabled"}:
        raise ValueError("Unsupported peer status")
    duplicate = find_peer_on_pop(db, agent.id, peer.asn, exclude_id=peer.id)
    if duplicate is not None:
        raise ValueError(f"AS{peer.asn} already has another peer (#{duplicate.id}) on this PoP.")
    endpoint = normalize_endpoint(endpoint)
    wg_public_key = normalize_wireguard_key(wg_public_key)
    local_link_address = normalize_link_local_address(local_link_address)
    peer_link_address = normalize_link_local_address(peer_link_address)
    peer.agent_id = agent.id
    peer.agent = agent
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
    """Tear the peer down on its router (best effort) and delete the row. Caller commits."""
    try:
        remove_peer(peer, peer.agent)
    except Exception as exc:
        logger.warning(
            "Could not tear down peer #%s on agent %s before delete: %s",
            peer.id,
            peer.agent.name,
            exc,
        )
    db.delete(peer)
