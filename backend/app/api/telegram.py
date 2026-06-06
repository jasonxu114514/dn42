import asyncio
import secrets
from typing import Any, Literal

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
from app.peer.config import peer_protocol_name
from app.peer.service import create_peer, delete_peer, derive_link_addresses, update_peer

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
    query_type: Literal["ping", "trace", "mtr", "route", "status"]
    target: str = Field(default="", max_length=255)


class PeerCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    agent: str = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
    endpoint: str = Field(min_length=1, max_length=255)
    wg_public_key: str = Field(min_length=1, max_length=128)


class PeerEditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    peer_id: int = Field(ge=1)
    endpoint: str = Field(min_length=1, max_length=255)
    wg_public_key: str = Field(min_length=1, max_length=128)


class PeerDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    peer_id: int = Field(ge=1)


class PeerStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")


def require_bot_secret(x_backend_secret: str = Header("")) -> None:
    """Guard the bot-only API: the shared secret must match in constant time.

    保護僅供 bot 使用的 API：共享密鑰需以定時比較核對，避免從回應時間逐位元推測密鑰。
    """
    settings = get_settings()
    if not secrets.compare_digest(x_backend_secret, settings.telegram_backend_secret):
        raise HTTPException(status_code=401, detail="Invalid bot secret")


@router.post(
    "/challenge", response_model=ChallengeResponse, dependencies=[Depends(require_bot_secret)]
)
def telegram_challenge(
    payload: ChallengeRequest, db: Session = Depends(get_db)
) -> ChallengeResponse:
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
    agent = (
        db.query(Agent).filter(Agent.name == payload.agent, Agent.enabled.is_(True)).one_or_none()
    )
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        return await AgentClient().query(agent, payload.query_type, payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/agents", dependencies=[Depends(require_bot_secret)])
def telegram_agents(db: Session = Depends(get_db)) -> dict[str, Any]:
    agents = db.query(Agent).filter(Agent.enabled.is_(True)).order_by(Agent.name).all()
    return {"agents": [{"name": agent.name, "location": agent.location} for agent in agents]}


def _peer_summary(peer: PeerRequest) -> dict[str, Any]:
    return {
        "id": peer.id,
        "agent": peer.agent.name,
        "asn": peer.asn,
        "deploy_status": peer.deploy_status,
        "deploy_output": peer.deploy_output,
    }


def _owned_peer(db: Session, telegram_user_id: str, peer_id: int) -> PeerRequest:
    user = get_user_by_telegram(db, telegram_user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Telegram account is not verified")
    peer = db.query(PeerRequest).filter(PeerRequest.id == peer_id).one_or_none()
    if peer is None or peer.user_id != user.id:
        raise HTTPException(status_code=404, detail="Peer not found")
    return peer


@router.post("/peer/create", dependencies=[Depends(require_bot_secret)])
def telegram_peer_create(
    payload: PeerCreateRequest, db: Session = Depends(get_db)
) -> dict[str, Any]:
    settings = get_settings()
    user = get_user_by_telegram(db, payload.telegram_user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Telegram account is not verified")
    agent = (
        db.query(Agent).filter(Agent.name == payload.agent, Agent.enabled.is_(True)).one_or_none()
    )
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        local_link_address, peer_link_address = derive_link_addresses(
            user.primary_asn, settings.local_asn
        )
        peer = create_peer(
            db,
            user=user,
            agent=agent,
            endpoint=payload.endpoint,
            wg_public_key=payload.wg_public_key,
            local_link_address=local_link_address,
            peer_link_address=peer_link_address,
            settings=settings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return _peer_summary(peer)


@router.post("/peer/edit", dependencies=[Depends(require_bot_secret)])
def telegram_peer_edit(payload: PeerEditRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    settings = get_settings()
    peer = _owned_peer(db, payload.telegram_user_id, payload.peer_id)
    try:
        update_peer(
            db,
            peer=peer,
            agent=peer.agent,
            endpoint=payload.endpoint,
            wg_public_key=payload.wg_public_key,
            local_link_address=peer.local_link_address,
            peer_link_address=peer.peer_link_address,
            status=peer.status,
            settings=settings,
            redeploy=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    db.commit()
    return _peer_summary(peer)


@router.post("/peer/delete", dependencies=[Depends(require_bot_secret)])
def telegram_peer_delete(
    payload: PeerDeleteRequest, db: Session = Depends(get_db)
) -> dict[str, Any]:
    peer = _owned_peer(db, payload.telegram_user_id, payload.peer_id)
    delete_peer(db, peer=peer)
    db.commit()
    return {"ok": True, "id": payload.peer_id}


@router.post("/status", dependencies=[Depends(require_bot_secret)])
async def telegram_status(
    payload: PeerStatusRequest, db: Session = Depends(get_db)
) -> dict[str, Any]:
    user = get_user_by_telegram(db, payload.telegram_user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Telegram account is not verified")
    peers = (
        db.query(PeerRequest)
        .filter(PeerRequest.user_id == user.id)
        .order_by(PeerRequest.created_at.desc())
        .all()
    )
    # Resolve every agent (lazy load) before awaiting so the Session is never touched inside gather.
    targets = [
        (peer.id, peer.agent, peer.asn, peer.deploy_status, peer_protocol_name(peer, peer.agent))
        for peer in peers
    ]

    client = AgentClient()

    async def fetch(agent: Agent, protocol_name: str) -> str:
        try:
            result = await client.peer_status(agent, protocol_name)
            return str(result.get("output", result))
        except Exception as exc:  # noqa: BLE001 - one dead agent must not fail the batch
            return f"status unavailable: {exc}"

    details = await asyncio.gather(
        *(fetch(agent, proto) for _id, agent, _asn, _ds, proto in targets)
    )
    return {
        "asn": user.primary_asn,
        "peers": [
            {
                "id": pid,
                "agent": agent.name,
                "asn": asn,
                "deploy_status": deploy_status,
                "detail": detail,
            }
            for (pid, agent, asn, deploy_status, _proto), detail in zip(
                targets, details, strict=True
            )
        ],
    }
