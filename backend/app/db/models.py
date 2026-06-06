from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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


class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    location: Mapped[str] = mapped_column(String(128), default="")
    url: Mapped[str] = mapped_column(String(512))
    token: Mapped[str] = mapped_column(String(255), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class PeerRequest(Base):
    __tablename__ = "peer_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    asn: Mapped[str] = mapped_column(String(32), index=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id"), index=True)
    tunnel_type: Mapped[str] = mapped_column(String(32), default="wireguard")
    endpoint: Mapped[str] = mapped_column(String(255))
    wg_public_key: Mapped[str] = mapped_column(String(128))
    local_link_address: Mapped[str] = mapped_column(String(128), default="")
    peer_link_address: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    admin_note: Mapped[str] = mapped_column(Text, default="")
    deploy_status: Mapped[str] = mapped_column(String(32), default="not_deployed", index=True)
    deploy_output: Mapped[str] = mapped_column(Text, default="")
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    agent: Mapped[Agent] = relationship()


class LGQuery(Base):
    __tablename__ = "lg_queries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id"), index=True)
    query_type: Mapped[str] = mapped_column(String(32))
    target: Mapped[str] = mapped_column(String(255))
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
