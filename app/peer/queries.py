"""Shared peer/node query helpers used by web and Telegram routes."""

from sqlalchemy.orm import Session, joinedload

from app.db.models import Node, PeerRequest


def peer_with_node(db: Session, peer_id: str) -> PeerRequest | None:
    return (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .filter(PeerRequest.id == peer_id)
        .one_or_none()
    )


def peers_for_user_with_nodes(db: Session, user_id: int) -> list[PeerRequest]:
    return (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .filter(PeerRequest.user_id == user_id)
        .order_by(PeerRequest.created_at.desc())
        .all()
    )


def owned_peer_with_node(db: Session, user_id: int, peer_id: str) -> PeerRequest | None:
    return (
        db.query(PeerRequest)
        .options(joinedload(PeerRequest.node))
        .filter(PeerRequest.id == peer_id, PeerRequest.user_id == user_id)
        .one_or_none()
    )


def enabled_node_by_id(db: Session, node_id: str) -> Node | None:
    return db.query(Node).filter(Node.id == node_id, Node.enabled.is_(True)).one_or_none()


def enabled_node_by_name(db: Session, name: str) -> Node | None:
    return db.query(Node).filter(Node.name == name, Node.enabled.is_(True)).one_or_none()
