import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import ASNIdentity, AuthChallenge, TelegramBinding, User, utcnow
from app.peer.validation import normalize_asn_number


def create_challenge(
    db: Session,
    purpose: str,
    telegram_user_id: str | None = None,
    telegram_chat_id: str | None = None,
    ttl_seconds: int = 600,
) -> AuthChallenge:
    challenge = AuthChallenge(
        token=secrets.token_urlsafe(32),
        purpose=purpose,
        telegram_user_id=telegram_user_id,
        telegram_chat_id=telegram_chat_id,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return challenge


def consume_challenge(db: Session, token: str, purpose: str) -> AuthChallenge:
    challenge = db.query(AuthChallenge).filter(AuthChallenge.token == token).one_or_none()
    if challenge is None:
        raise ValueError("Unknown auth challenge")
    if challenge.purpose != purpose:
        raise ValueError("Auth challenge purpose mismatch")
    if challenge.consumed_at is not None:
        raise ValueError("Auth challenge was already used")
    expires_at = challenge.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise ValueError("Auth challenge has expired")
    challenge.consumed_at = utcnow()
    db.commit()
    db.refresh(challenge)
    return challenge


def upsert_user_from_kioubit(db: Session, data: dict[str, Any], settings: Settings) -> User:
    asn = str(data["asn"])
    user = db.query(User).filter(User.primary_asn == asn).one_or_none()
    if user is None:
        user = User(primary_asn=asn)
        db.add(user)
    user.first_email = data.get("first_email") or user.first_email
    try:
        user.is_admin = normalize_asn_number(asn) == normalize_asn_number(settings.local_asn)
    except ValueError:
        user.is_admin = False
    user.last_login_at = utcnow()
    db.commit()
    db.refresh(user)

    identity = ASNIdentity(
        user_id=user.id,
        asn=asn,
        mnt_json=json.dumps(data.get("mnt", [])),
        effective_mnt=data.get("effective_mnt"),
        allowed4_json=json.dumps(data.get("allowed4", [])),
        allowed6_json=json.dumps(data.get("allowed6", [])),
        authtype=data.get("authtype"),
    )
    db.add(identity)
    db.commit()
    return user


def bind_telegram(
    db: Session,
    user: User,
    telegram_user_id: str,
    telegram_chat_id: str,
    username: str | None = None,
) -> TelegramBinding:
    binding = (
        db.query(TelegramBinding)
        .filter(TelegramBinding.telegram_user_id == telegram_user_id)
        .one_or_none()
    )
    if binding is None:
        binding = TelegramBinding(
            user_id=user.id,
            telegram_user_id=telegram_user_id,
            telegram_chat_id=telegram_chat_id,
            username=username,
        )
        db.add(binding)
    else:
        binding.user_id = user.id
        binding.telegram_chat_id = telegram_chat_id
        binding.username = username
        binding.linked_at = utcnow()
    db.commit()
    db.refresh(binding)
    return binding


def get_user_by_telegram(db: Session, telegram_user_id: str) -> User | None:
    binding = (
        db.query(TelegramBinding)
        .filter(TelegramBinding.telegram_user_id == telegram_user_id)
        .one_or_none()
    )
    if binding is None:
        return None
    return db.query(User).filter(User.id == binding.user_id).one_or_none()
