from typing import Any
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.auth.kioubit import KioubitAuthError, KioubitVerifier
from app.auth.service import (
    bind_telegram,
    consume_challenge,
    create_challenge,
    get_user_by_telegram,
    upsert_user_from_kioubit,
)
from app.config import get_settings
from app.db.models import Agent, PeerRequest
from app.db.session import get_db
from app.lg.client import AgentClient

router = APIRouter(prefix="/api/telegram", tags=["telegram"])


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    telegram_chat_id: str = Field(pattern=r"^-?\d{1,20}$")


class ChallengeResponse(BaseModel):
    token: str
    url: str


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    telegram_chat_id: str = Field(pattern=r"^-?\d{1,20}$")
    username: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_]{1,64}$")
    params: str = Field(min_length=1, max_length=8192)
    signature: str = Field(min_length=1, max_length=8192)


class LGRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    agent: str = Field(default="local", pattern=r"^[A-Za-z0-9_-]{1,64}$")
    query_type: Literal["ping", "mtr", "route", "status"]
    target: str = Field(default="", max_length=255)


def require_bot_secret(x_backend_secret: str = Header("")) -> None:
    settings = get_settings()
    if x_backend_secret != settings.telegram_backend_secret:
        raise HTTPException(status_code=401, detail="Invalid bot secret")


@router.post("/challenge", response_model=ChallengeResponse, dependencies=[Depends(require_bot_secret)])
def telegram_challenge(payload: ChallengeRequest, db: Session = Depends(get_db)) -> ChallengeResponse:
    settings = get_settings()
    challenge = create_challenge(
        db,
        purpose="telegram",
        telegram_user_id=payload.telegram_user_id,
        telegram_chat_id=payload.telegram_chat_id,
    )
    return ChallengeResponse(
        token=challenge.token,
        url=f"{settings.base_url}/telegram/auth?token={challenge.token}",
    )


@router.post("/verify", dependencies=[Depends(require_bot_secret)])
def telegram_verify(payload: VerifyRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    settings = get_settings()
    verifier = KioubitVerifier(settings.kioubit_public_key_path, settings.auth_domain)
    try:
        data = verifier.verify(params=payload.params, signature=payload.signature)
        challenge = consume_challenge(db, data.get("user_token", ""), purpose="telegram")
        if challenge.telegram_user_id != payload.telegram_user_id:
            raise ValueError("Telegram user mismatch")
        user = upsert_user_from_kioubit(db, data, settings)
        bind_telegram(
            db,
            user,
            telegram_user_id=payload.telegram_user_id,
            telegram_chat_id=payload.telegram_chat_id,
            username=payload.username,
        )
    except (KioubitAuthError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": True,
        "asn": user.primary_asn,
        "effective_mnt": data.get("effective_mnt"),
        "authtype": data.get("authtype"),
    }


@router.get("/peer/{telegram_user_id}", dependencies=[Depends(require_bot_secret)])
def telegram_peer_status(telegram_user_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = get_user_by_telegram(db, telegram_user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Telegram account is not verified")
    peers = (
        db.query(PeerRequest)
        .filter(PeerRequest.user_id == user.id)
        .order_by(PeerRequest.created_at.desc())
        .all()
    )
    return {
        "asn": user.primary_asn,
        "peers": [
            {
                "id": peer.id,
                "agent": peer.agent.name,
                "status": peer.status,
                "endpoint": peer.endpoint,
                "created_at": peer.created_at.isoformat(),
            }
            for peer in peers
        ],
    }


@router.post("/lg", dependencies=[Depends(require_bot_secret)])
async def telegram_lg(payload: LGRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    user = get_user_by_telegram(db, payload.telegram_user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Telegram account is not verified")
    agent = db.query(Agent).filter(Agent.name == payload.agent, Agent.enabled.is_(True)).one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        return await AgentClient().query(agent, payload.query_type, payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
