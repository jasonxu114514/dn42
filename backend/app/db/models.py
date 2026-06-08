import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base
from app.peer.validation import DEFAULT_WIREGUARD_MTU


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_uuid() -> str:
    """Primary-key default for Nodes and peers: a random UUID4 as a 36-char string.

    Stored as ``String(36)`` (SQLite has no native UUID type). UUIDs replace the old
    auto-increment integers so ids in URLs are not enumerable and reveal no ordering/count.
    主鍵預設值:隨機 UUID4(36 字元字串)。以 UUID 取代自增整數,使網址中的 id 不可列舉、
    不洩漏數量與順序。"""
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    primary_asn: Mapped[str] = mapped_column(String(32), index=True, unique=True)
    first_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    identities: Mapped[list["ASNIdentity"]] = relationship(back_populates="user")
    telegram_bindings: Mapped[list["TelegramBinding"]] = relationship(back_populates="user")


class ASNIdentity(Base):
    __tablename__ = "asn_identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    asn: Mapped[str] = mapped_column(String(32), index=True)
    mnt_json: Mapped[str] = mapped_column(Text, default="[]")
    effective_mnt: Mapped[str | None] = mapped_column(String(128), nullable=True)
    allowed4_json: Mapped[str] = mapped_column(Text, default="[]")
    allowed6_json: Mapped[str] = mapped_column(Text, default="[]")
    authtype: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="identities")


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(32), index=True)
    telegram_user_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    telegram_chat_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TelegramBinding(Base):
    __tablename__ = "telegram_bindings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    telegram_user_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    telegram_chat_id: Mapped[str] = mapped_column(String(64), index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship(back_populates="telegram_bindings")


class Node(Base):
    """A point of presence (PoP) the operator runs: a router reachable over WireGuard whose Go
    agent dials the control plane over WSS. Renamed from ``Agent`` — the on-router daemon is still
    "the agent", but the control-plane concept is a Node.
    節點(PoP):由操作者經營、可經 WireGuard 連線的路由器,其上的 Go agent 以 WSS 連回控制平面。"""

    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    location: Mapped[str] = mapped_column(String(128), default="")
    # The Node's public address: a bare IPv4/IPv6/domain (no scheme/port), validated by
    # normalize_node_host. Peers dial it over WireGuard; the listen port is derived from the
    # peer's ASN. (The agent's own control channel is the WSS it dials out on, not this field.)
    url: Mapped[str] = mapped_column(String(512))
    token: Mapped[str] = mapped_column(String(255), default="")
    # Our WireGuard public key on this Node, reported by the agent over WSS and shown to peers in
    # their generated config. Empty until the first heartbeat/pubkey refresh.
    # 本節點的 WireGuard 公鑰,由 agent 透過 WSS 回報,並填入對等端產生的設定。首次同步前為空。
    wg_public_key: Mapped[str] = mapped_column(String(128), default="")
    # Per-Node dn42 identity (admin-editable, independent per node). asn falls back to LOCAL_ASN
    # when blank (see node_effective_asn); dn42_ipv4/dn42_ipv6 are the node's dn42 addresses shown
    # to peers. 每節點各自的 dn42 身分(admin 可編輯):asn 留空時退回 LOCAL_ASN。
    asn: Mapped[str] = mapped_column(String(32), default="")
    dn42_ipv4: Mapped[str] = mapped_column(String(64), default="")
    dn42_ipv6: Mapped[str] = mapped_column(String(64), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    system_status_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PeerRequest(Base):
    __tablename__ = "peer_requests"
    __table_args__ = (UniqueConstraint("node_id", "asn", name="uq_peer_node_asn"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    asn: Mapped[str] = mapped_column(String(32), index=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    tunnel_type: Mapped[str] = mapped_column(String(32), default="wireguard")
    endpoint: Mapped[str] = mapped_column(String(255), default="")
    wg_public_key: Mapped[str] = mapped_column(String(128))
    wg_mtu: Mapped[int] = mapped_column(
        Integer, default=DEFAULT_WIREGUARD_MTU, server_default=str(DEFAULT_WIREGUARD_MTU)
    )
    local_link_address: Mapped[str] = mapped_column(String(128), default="")
    peer_link_address: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    admin_note: Mapped[str] = mapped_column(Text, default="")
    deploy_status: Mapped[str] = mapped_column(String(32), default="not_deployed", index=True)
    deploy_output: Mapped[str] = mapped_column(Text, default="")
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    node: Mapped[Node] = relationship()


class LGQuery(Base):
    __tablename__ = "lg_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id"), index=True)
    query_type: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(255))
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Read-only convenience relationships for the admin audit log (joinedload avoids N+1 queries).
    # user_id is nullable (public queries), so the user relationship may be None.
    node: Mapped["Node"] = relationship()
    user: Mapped["User | None"] = relationship()
