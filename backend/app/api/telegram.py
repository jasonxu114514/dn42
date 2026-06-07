import asyncio
import secrets
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.auth.findnoc import FindNocError, query_user_asns, verify_control
from app.auth.kioubit import KioubitAuthError, KioubitVerifier
from app.auth.service import (
    bind_telegram,
    consume_challenge,
    create_challenge,
    get_user_by_telegram,
    unbind_telegram,
    upsert_user_from_findnoc,
    upsert_user_from_kioubit,
)
from app.config import get_settings
from app.db.models import Agent, PeerRequest
from app.db.session import get_db
from app.lg.client import AgentClient
from app.peer.config import peer_protocol_name, peering_info
from app.peer.service import create_peer, delete_peer, derive_link_addresses, update_peer
from app.peer.validation import MAX_WIREGUARD_MTU, MIN_WIREGUARD_MTU, normalize_asn_number

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
    wg_mtu: int | None = Field(default=None, ge=MIN_WIREGUARD_MTU, le=MAX_WIREGUARD_MTU)


class PeerEditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    peer_id: int = Field(ge=1)
    endpoint: str = Field(min_length=1, max_length=255)
    wg_public_key: str = Field(min_length=1, max_length=128)
    wg_mtu: int | None = Field(default=None, ge=MIN_WIREGUARD_MTU, le=MAX_WIREGUARD_MTU)


class PeerDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    peer_id: int = Field(ge=1)


class PeerStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")


class FindNocLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    telegram_user_id: str = Field(pattern=r"^\d{1,20}$")
    telegram_chat_id: str = Field(pattern=r"^-?\d{1,20}$")
    username: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_]{1,64}$")
    # Optional: the ASN the user picked from a multi-ASN result. Re-checked against FindNOC and
    # normalised in the handler (reusing normalize_asn_number).
    asn: str | None = Field(default=None, max_length=16)


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


@router.post("/findnoc/login", dependencies=[Depends(require_bot_secret)])
async def telegram_findnoc_login(
    payload: FindNocLoginRequest, db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Quick Telegram login via FindNOC: bind the caller's verified UID to the ASN it controls.

    Status contract the bot relies on: 404 = UID not in FindNOC, 503 = feature off / upstream down
    (both → the bot falls back to Kioubit), 400 = a real error to surface (only on the asn path).
    The UID is the bot-vouched Telegram sender id, and the ASN is always re-checked against the live
    FindNOC API, so a client-supplied ``asn`` cannot grant access FindNOC does not confirm.
    透過 FindNOC 快速登入:404=UID 不在 FindNOC、503=未設定/上游故障(兩者皆使 bot 回退 Kioubit)、
    400=須回報的錯誤。ASN 一律對 FindNOC 即時複查,故用戶端帶入的 asn 無法越權。
    """
    settings = get_settings()
    if not settings.findnoc_enabled:
        raise HTTPException(status_code=503, detail="FindNOC login is not configured")
    uid = payload.telegram_user_id
    try:
        if payload.asn is not None:
            try:
                asn_number = normalize_asn_number(payload.asn)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            if not await verify_control(uid, asn_number, settings):
                raise HTTPException(
                    status_code=400,
                    detail=f"FindNOC has no record that you control AS{asn_number}",
                )
            asns = [asn_number]
        else:
            asns = await query_user_asns(uid, settings)
            if not asns:
                raise HTTPException(
                    status_code=404, detail="Your Telegram account is not registered in FindNOC"
                )
            if len(asns) > 1:
                # Let the user pick; the chosen ASN comes back on a follow-up call and is verified.
                return {"need_choice": True, "asns": [f"AS{a}" for a in asns]}
    except FindNocError as exc:
        raise HTTPException(status_code=503, detail="FindNOC is currently unavailable") from exc

    asn_number = asns[0]
    user = upsert_user_from_findnoc(db, asn_number, settings)
    bind_telegram(
        db,
        user,
        telegram_user_id=payload.telegram_user_id,
        telegram_chat_id=payload.telegram_chat_id,
        username=payload.username,
    )
    return {"ok": True, "asn": user.primary_asn, "method": "findnoc"}


@router.post("/logout", dependencies=[Depends(require_bot_secret)])
def telegram_logout(payload: LogoutRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Unlink the caller's Telegram account from its dn42 ASN (the bot's /logout).

    404 when the account is not linked, so the bot can show its standard "not linked" message.
    The user's peers are kept (they reference the user, not the Telegram binding) and reappear on
    a future /login. 未連結時回 404,使 bot 顯示其標準「未連結」訊息;對等保留,日後 /login 重新出現。
    """
    user = get_user_by_telegram(db, payload.telegram_user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Telegram account is not verified")
    unbind_telegram(db, payload.telegram_user_id)
    return {"ok": True, "asn": user.primary_asn}


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
                "wg_mtu": peer.wg_mtu,
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
        "wg_mtu": peer.wg_mtu,
        # The "our side" details the peer needs to configure their end; the bot shows these once
        # the deploy succeeds. 部署成功後 bot 會把這些「我方」參數回給使用者設定對端。
        "peering": peering_info(peer, peer.agent),
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
            wg_mtu=payload.wg_mtu,
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
            wg_mtu=payload.wg_mtu,
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

    client = AgentClient()

    async def fetch(agent: Agent, protocol_name: str) -> dict[str, str]:
        # One agent round-trip returns both the BIRD protocol detail (``output``) and the
        # WireGuard tunnel status (``wireguard``); a dead agent degrades to a message without
        # failing the batch.
        # 單次 agent 往返同時回傳 BIRD protocol 細節(``output``)與 WireGuard 隧道狀態
        # (``wireguard``);agent 失聯時退化為訊息,不使整批失敗。
        try:
            result = await client.peer_status(agent, protocol_name)
            return {
                "detail": str(result.get("output", result)),
                "wg_detail": str(result.get("wireguard", "")),
            }
        except Exception as exc:  # noqa: BLE001 - one dead agent must not fail the batch
            return {"detail": f"status unavailable: {exc}", "wg_detail": ""}

    # Read every ORM field (agent, peering, protocol name) up front so the Session is never touched
    # inside the gather below; the per-peer BGP queries then run concurrently over loaded data.
    # 先一次讀完所有 ORM 欄位,之後 gather 內僅做網路查詢,不再碰 Session。
    snapshots: list[dict[str, Any]] = []
    fetches = []
    for peer in peers:
        agent = peer.agent
        snapshots.append(
            {
                "id": peer.id,
                "agent": agent.name,
                "asn": peer.asn,
                "status": peer.status,
                "endpoint": peer.endpoint,
                "wg_mtu": peer.wg_mtu,
                "deploy_status": peer.deploy_status,
                "peering": peering_info(peer, agent),
            }
        )
        fetches.append(fetch(agent, peer_protocol_name(peer, agent)))

    details = await asyncio.gather(*fetches)
    return {
        "asn": user.primary_asn,
        "peers": [{**snap, **detail} for snap, detail in zip(snapshots, details, strict=True)],
    }
