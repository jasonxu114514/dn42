import json
import secrets
from datetime import UTC, datetime, timedelta
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
        expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
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
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at < datetime.now(UTC):
        raise ValueError("Auth challenge has expired")
    challenge.consumed_at = utcnow()
    db.commit()
    db.refresh(challenge)
    return challenge


def _upsert_user_for_asn(
    db: Session, asn: str, settings: Settings, *, first_email: str | None = None
) -> User:
    """Create or update the ``User`` for ``asn`` and (re)compute admin status; return the User.

    Shared by every login source (Kioubit, FindNOC) so they agree on identity and admin rules: admin
    is granted when the verified ASN equals ``settings.local_asn``. Callers append their own
    ``ASNIdentity`` audit row. ``asn`` must already be in the canonical bare-number form used by
    ``User.primary_asn``, so the same operator maps to one row regardless of login method.
    每個登入來源共用:依 ASN 建立/更新 User 並重算管理員旗標(ASN 等於 local_asn 時授予);呼叫者各自
    附上 ASNIdentity 稽核列。``asn`` 須為與 primary_asn 一致的裸數字形式。
    """
    user = db.query(User).filter(User.primary_asn == asn).one_or_none()
    if user is None:
        user = User(primary_asn=asn)
        db.add(user)
    if first_email:
        user.first_email = first_email
    try:
        user.is_admin = normalize_asn_number(asn) == normalize_asn_number(settings.local_asn)
    except ValueError:
        user.is_admin = False
    user.last_login_at = utcnow()
    db.commit()
    db.refresh(user)
    return user


def upsert_user_from_kioubit(db: Session, data: dict[str, Any], settings: Settings) -> User:
    asn = str(data["asn"])
    user = _upsert_user_for_asn(db, asn, settings, first_email=data.get("first_email"))
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


def upsert_user_from_findnoc(db: Session, asn_number: str, settings: Settings) -> User:
    """Create/update the User for a FindNOC-verified ASN and record a minimal identity row.

    ``asn_number`` is the bare numeric ASN (already normalised via ``normalize_asn_number``).
    FindNOC supplies no maintainer/route metadata, so the ``ASNIdentity`` keeps its empty-list
    defaults and only records ``authtype="findnoc"`` so the audit log shows how it was verified.
    """
    user = _upsert_user_for_asn(db, asn_number, settings)
    identity = ASNIdentity(user_id=user.id, asn=asn_number, authtype="findnoc")
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
    return (
        db.query(User)
        .join(TelegramBinding, TelegramBinding.user_id == User.id)
        .filter(TelegramBinding.telegram_user_id == telegram_user_id)
        .one_or_none()
    )


def unbind_telegram(db: Session, telegram_user_id: str) -> bool:
    """Remove the Telegram↔ASN link for ``telegram_user_id``; return whether one existed.

    Only the ``TelegramBinding`` row is deleted — the ``User`` and its peers (which reference the
    user, not the binding) are left intact, so a later ``/login`` re-links the same account and the
    peers reappear. Used by the bot's ``/logout`` command.
    僅刪除 ``TelegramBinding`` 列——``User`` 與其對等(參照 user 而非 binding)保持不變,故日後
    ``/login`` 會重新連結同一帳號且對等重新出現。供 bot 的 ``/logout`` 指令使用。
    """
    binding = (
        db.query(TelegramBinding)
        .filter(TelegramBinding.telegram_user_id == telegram_user_id)
        .one_or_none()
    )
    if binding is None:
        return False
    db.delete(binding)
    db.commit()
    return True
