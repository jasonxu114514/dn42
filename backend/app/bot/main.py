import asyncio
import json
import random
import re
import secrets
from collections.abc import Awaitable
from typing import Any

import httpx
from aiogram import Bot, Dispatcher, F
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup, default_state
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    WebAppInfo,
)

from app.config import get_settings

settings = get_settings()

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")

NOT_LINKED_MSG = "Your Telegram account is not linked to a dn42 ASN yet. Use /login first."


class Backend:
    """Backend HTTP client. Holds one pooled AsyncClient reused for the bot's lifetime."""

    def __init__(self) -> None:
        self.base_url = settings.bot_backend_url.rstrip("/")
        self.headers = {"X-Backend-Secret": settings.telegram_backend_secret}
        self._client: httpx.AsyncClient | None = None

    def _http(self) -> httpx.AsyncClient:
        # Created lazily so the client binds to the running event loop, then reused so every
        # backend call shares one connection pool instead of opening a fresh connection.
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url, headers=self.headers, timeout=30
            )
        return self._client

    async def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = await self._http().post(path, json=payload, timeout=40)
        response.raise_for_status()
        return response.json()

    async def get(self, path: str) -> dict[str, Any]:
        response = await self._http().get(path)
        response.raise_for_status()
        return response.json()

    async def aclose(self) -> None:
        """Close the pooled client on shutdown. Safe to call even if it was never created."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None


backend = Backend()
dp = Dispatcher()


class CreatePeer(StatesGroup):
    agent = State()
    endpoint = State()
    public_key = State()


class EditPeer(StatesGroup):
    choosing = State()
    endpoint = State()
    public_key = State()


class DeletePeer(StatesGroup):
    choosing = State()
    confirming = State()


HELP_TEXT = (
    "dn42 autopeer bot\n\n"
    "/login - link your dn42 ASN (Kioubit)\n"
    "/peer (or /status) - your peers: state, our-side params, and live BGP status\n"
    "/create - create a peer (guided)\n"
    "/edit - edit one of your peers (guided)\n"
    "/delete - delete one of your peers (guided)\n"
    "/ping <ip-or-host> - random PoP; tap a button to switch\n"
    "/trace <ip-or-host> - random PoP; tap a button to switch\n"
    "/route <prefix-or-ip> - random PoP; tap a button to switch\n"
    "/cancel - abort the current guided action"
)


def user_payload(message: Message) -> dict[str, str]:
    return {
        "telegram_user_id": str(message.from_user.id),
        "telegram_chat_id": str(message.chat.id),
    }


def detail_of(exc: httpx.HTTPStatusError) -> str:
    """Pull the FastAPI ``detail`` out of an error response, falling back to the raw body."""
    try:
        payload = exc.response.json()
    except ValueError:
        return exc.response.text
    return str(payload.get("detail", exc.response.text))


async def call_backend(
    message: Message,
    request: Awaitable[dict[str, Any]],
    *,
    error_prefix: str,
    reply_markup: ReplyKeyboardRemove | None = None,
    not_found_message: str | None = None,
) -> dict[str, Any] | None:
    """Await a backend call; on any HTTP error, answer the user and return ``None``.

    集中處理 bot 對後端呼叫的錯誤：成功回傳解析後的 JSON；發生 HTTP 錯誤時，向使用者回覆乾淨的
    訊息（4xx 取 FastAPI 的 ``detail``）並回傳 None。404 可用 ``not_found_message`` 客製。
    """
    try:
        return await request
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404 and not_found_message is not None:
            await message.answer(not_found_message, reply_markup=reply_markup)
        else:
            await message.answer(f"{error_prefix}: {detail_of(exc)}", reply_markup=reply_markup)
        return None
    except httpx.HTTPError as exc:
        await message.answer(f"{error_prefix}: {exc}", reply_markup=reply_markup)
        return None


def format_block(text: str, limit: int = 3900) -> str:
    text = text or "(no output)"
    if len(text) > limit:
        text = text[:limit] + "\n...[truncated]"
    return f"```\n{text}\n```"


def chunk_blocks(blocks: list[str], limit: int = 3900) -> list[str]:
    """Pack ``=== peer ===`` blocks into as few messages as fit, splitting only at boundaries."""
    messages: list[str] = []
    current = ""
    for block in blocks:
        if len(block) > limit:
            block = block[:limit] + "\n...[truncated]"
        if current and len(current) + 1 + len(block) > limit:
            messages.append(current)
            current = block
        else:
            current = f"{current}\n{block}" if current else block
    if current:
        messages.append(current)
    return messages


def looks_like_endpoint(value: str) -> bool:
    host, sep, port = value.rpartition(":")
    return bool(sep and host and port.isdigit() and 1 <= int(port) <= 65535)


def parse_peer_id(text: str | None) -> int | None:
    if not text:
        return None
    cleaned = text.strip().lstrip("#").strip()
    return int(cleaned) if cleaned.isdigit() else None


def peer_list_text(peers: list[dict]) -> str:
    return "\n".join(f"#{p['id']} {p['agent']} {p['status']} {p['endpoint']}" for p in peers)


def agent_keyboard(agents: list[dict]) -> ReplyKeyboardMarkup:
    rows = [[KeyboardButton(text=agent["name"])] for agent in agents]
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=True)


def peer_keyboard(peers: list[dict]) -> ReplyKeyboardMarkup:
    rows = [[KeyboardButton(text=f"#{p['id']}")] for p in peers]
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=True)


def lg_agent_inline_keyboard(
    agent_names: list[str], token: str, active: str | None = None
) -> InlineKeyboardMarkup:
    """Buttons (≤3 per row) for picking the looking-glass PoP; ``active`` gets a • marker.

    callback_data carries only ``lg:<token>:<index>`` — never the target — so it stays well
    within Telegram's 64-byte limit even for long IPv6/hostname targets. ``token`` ties the
    buttons to the FSM entry created for this command (see ``run_lg``/``lg_choose``).
    callback_data 僅帶 ``lg:<token>:<index>``（不含目標），即使目標為長 IPv6／主機名也遠低於
    Telegram 的 64 byte 上限；``token`` 將按鈕綁定到該次指令建立的 FSM 記錄；``active`` 為目前
    顯示輸出的 PoP，加上 • 標記。
    """
    buttons = [
        InlineKeyboardButton(
            text=f"• {name}" if name == active else name,
            callback_data=f"lg:{token}:{index}",
        )
        for index, name in enumerate(agent_names)
    ]
    rows = [buttons[i : i + 3] for i in range(0, len(buttons), 3)]
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def reject_if_command(message: Message, action: str) -> bool:
    """Stop a stray slash-command from being stored as a wizard field value."""
    if message.text and message.text.strip().startswith("/"):
        await message.answer(f"You're in the middle of /{action}. Send /cancel to abort.")
        return True
    return False


async def load_user_peers(message: Message) -> list[dict] | None:
    """Return the caller's peers, or None after answering with the reason (unverified / error)."""
    data = await call_backend(
        message,
        backend.get(f"/api/telegram/peer/{message.from_user.id}"),
        error_prefix="Could not load your peers",
        not_found_message=NOT_LINKED_MSG,
    )
    if data is None:
        return None
    return data.get("peers", [])


def peering_info_lines(info: dict) -> str:
    """The three "our side" parameters a peer copies into their own WireGuard/BGP config.

    我方端點／公鑰／隧道內位址,供對端填入自己的 WireGuard 與 BGP 設定。
    """
    return (
        f"our endpoint:  {info.get('endpoint', '')}\n"
        f"our pubkey:    {info.get('public_key', '')}\n"
        f"our tunnel IP: {info.get('tunnel_ip', '')}  (your BGP neighbor)"
    )


def peering_info_text(info: dict) -> str:
    """The our-side block shown after a successful deploy: a caption plus the parameters."""
    return "Configure your side with our details:\n" + peering_info_lines(info)


async def send_peer_result(message: Message, action: str, result: dict) -> None:
    deploy_status = result.get("deploy_status")
    await message.answer(
        f"{action} peer #{result.get('id')} on {result.get('agent')} "
        f"(AS{result.get('asn')}) — deploy: {deploy_status}",
        reply_markup=ReplyKeyboardRemove(),
    )
    # On success show the actionable "our side" parameters; otherwise show the deploy output so the
    # failure reason is visible. 成功時顯示可操作的「我方」參數,失敗時顯示部署輸出以呈現原因。
    if deploy_status == "deployed" and result.get("peering"):
        block = format_block(peering_info_text(result["peering"]))
        await message.answer(block, parse_mode="Markdown")
        return
    output = str(result.get("deploy_output", "")).strip()
    if output:
        await message.answer(format_block(output, 1500), parse_mode="Markdown")


async def handle_endpoint_step(
    message: Message, state: FSMContext, *, action: str, next_state: State, prompt: str
) -> None:
    """Shared create/edit wizard step: validate a host:port endpoint, store it, advance state."""
    if await reject_if_command(message, action):
        return
    endpoint = (message.text or "").strip()
    if not looks_like_endpoint(endpoint):
        await message.answer(
            "Endpoint must be host:port (e.g. 198.51.100.7:51820). Try again or /cancel."
        )
        return
    await state.update_data(endpoint=endpoint)
    await state.set_state(next_state)
    await message.answer(prompt)


# --- Help & verification -------------------------------------------------------------------


@dp.message(Command("start", "help"), default_state)
async def help_cmd(message: Message) -> None:
    await message.answer(HELP_TEXT)


@dp.message(Command("verify", "login"), default_state)
async def verify_cmd(message: Message) -> None:
    data = await call_backend(
        message,
        backend.post("/api/telegram/challenge", user_payload(message)),
        error_prefix="Could not create verification challenge",
    )
    if data is None:
        return

    url = data["url"]
    if not url.startswith("https://"):
        await message.answer(
            "Telegram Web Apps require DOMAIN to use HTTPS.\n"
            f"Current verification URL is: {url}\n\n"
            "Set DOMAIN to a public HTTPS domain and restart both the backend and bot."
        )
        return

    keyboard = ReplyKeyboardMarkup(
        keyboard=[
            [
                KeyboardButton(
                    text="Start Kioubit Verification",
                    web_app=WebAppInfo(url=url),
                )
            ]
        ],
        resize_keyboard=True,
        one_time_keyboard=True,
    )
    await message.answer("Open the app to verify your dn42 ASN:", reply_markup=keyboard)


@dp.message(F.web_app_data)
async def web_app_data(message: Message) -> None:
    try:
        envelope = json.loads(message.web_app_data.data)
        payload = {
            **user_payload(message),
            "username": message.from_user.username,
            "params": envelope["params"],
            "signature": envelope["signature"],
        }
    except (KeyError, json.JSONDecodeError) as exc:
        await message.answer(f"Verification data was malformed: {exc}")
        return

    result = await call_backend(
        message,
        backend.post("/api/telegram/verify", payload),
        error_prefix="Verification failed",
    )
    if result is None:
        return

    await message.answer(
        "ASN verification complete.\n"
        f"ASN: AS{result['asn']}\n"
        f"Maintainer: {result.get('effective_mnt') or 'unknown'}\n"
        f"Method: {result.get('authtype') or 'unknown'}"
    )


# --- Peer list & status --------------------------------------------------------------------


@dp.message(Command("peer", "status"), default_state)
async def peers_cmd(message: Message) -> None:
    """Unified peer view (merges /peer and /status): one block per peer with its state, the
    our-side params to hand the other operator, and its live BGP status.

    合併 /peer 與 /status:每個對等一個區塊,含狀態、提供對端的我方參數與即時 BGP 狀態。
    """
    result = await call_backend(
        message,
        backend.post("/api/telegram/status", {"telegram_user_id": str(message.from_user.id)}),
        error_prefix="Peer lookup failed",
        not_found_message=NOT_LINKED_MSG,
    )
    if result is None:
        return

    peers = result.get("peers", [])
    if not peers:
        await message.answer("You have no peers yet. Use /create to add one.")
        return
    blocks = []
    for peer in peers:
        label = " · ".join(filter(None, (peer.get("status"), peer.get("deploy_status"))))
        lines = [f"=== #{peer['id']} {peer['agent']} (AS{peer['asn']}) [{label}] ==="]
        if peer.get("endpoint"):
            lines.append(f"your endpoint: {peer['endpoint']}")
        if peer.get("peering"):
            lines.append(peering_info_lines(peer["peering"]))
        body = str(peer.get("detail", "")).strip() or "(no detail)"
        blocks.append("\n".join(lines) + f"\n\n{body}")
    for chunk in chunk_blocks(blocks):
        await message.answer(f"```\n{chunk}\n```", parse_mode="Markdown")


# --- Looking glass -------------------------------------------------------------------------


def parse_lg_target(message: Message) -> str:
    """Pull the single target out of ``/<command> <target>``.

    The PoP/agent is no longer a positional argument — it is chosen from the inline buttons
    attached to the reply — so any extra tokens are ignored.
    PoP／agent 不再是位置參數（改由回覆訊息上的內嵌按鈕選擇），因此會忽略多餘的 token。
    """
    parts = (message.text or "").split()
    if len(parts) < 2:
        raise ValueError("Usage: /<command> <target>")
    return parts[1]


async def run_lg(message: Message, state: FSMContext, query_type: str) -> None:
    """Run the query on a random PoP immediately, then let the user switch PoPs via buttons.

    立即在隨機 PoP 上執行，並附按鈕讓使用者切換 PoP（結果就地以 edit 更新）。
    """
    try:
        target = parse_lg_target(message)
    except ValueError as exc:
        await message.answer(str(exc))
        return
    data = await call_backend(
        message,
        backend.get("/api/telegram/agents"),
        error_prefix="Could not load agents",
    )
    if data is None:
        return
    names = [agent["name"] for agent in data.get("agents", [])]
    if not names:
        await message.answer("No agents are available right now.")
        return
    # A fresh token per command so a tap only runs against the query it was shown with; a newer
    # /ping|/trace|/route overwrites it, expiring the previous message's buttons (see lg_choose).
    # 每次指令產生新 token：點擊只會對其所屬查詢生效；較新的 LG 指令會覆蓋它，使舊訊息的按鈕失效。
    token = secrets.token_urlsafe(6)
    await state.update_data(
        lg_token=token, lg_query_type=query_type, lg_target=target, lg_agents=names
    )
    # Pick a random PoP and show output right away; the user can switch via the buttons.
    # 隨機挑一個 PoP 立即顯示輸出；使用者可再用按鈕切換。
    agent = random.choice(names)
    placeholder = await message.answer(
        format_block(f"{query_type} {target} @ {agent}\n\nrunning…"),
        parse_mode="Markdown",
        reply_markup=lg_agent_inline_keyboard(names, token, active=agent),
    )
    await render_lg(
        placeholder,
        user_id=message.from_user.id,
        query_type=query_type,
        target=target,
        agent=agent,
        names=names,
        token=token,
    )


async def render_lg(
    message: Message,
    *,
    user_id: int,
    query_type: str,
    target: str,
    agent: str,
    names: list[str],
    token: str,
) -> None:
    """Run one looking-glass query and edit ``message`` in place with the labelled output.

    The keyboard is re-attached (``agent`` marked) so the user can keep switching PoPs on the
    same message; an HTTP error is shown in the block rather than as a separate message.
    重新附上鍵盤（標記 ``agent``）讓使用者可在同一訊息持續切換 PoP；HTTP 錯誤直接顯示於區塊內。
    """
    try:
        result = await backend.post(
            "/api/telegram/lg",
            {
                "telegram_user_id": str(user_id),
                "agent": agent,
                "query_type": query_type,
                "target": target,
            },
        )
        body = str(result.get("output", result))
    except httpx.HTTPStatusError as exc:
        body = f"Looking glass failed: {detail_of(exc)}"
    except httpx.HTTPError as exc:
        body = f"Looking glass failed: {exc}"
    text = format_block(f"{query_type} {target} @ {agent}\n\n{body}")
    try:
        await message.edit_text(
            text,
            parse_mode="Markdown",
            reply_markup=lg_agent_inline_keyboard(names, token, active=agent),
        )
    except TelegramBadRequest:
        # e.g. "message is not modified" when the same PoP is tapped twice with identical output.
        pass


@dp.callback_query(F.data.startswith("lg:"))
async def lg_choose(callback: CallbackQuery, state: FSMContext) -> None:
    """Re-run the query on the tapped PoP and edit the message output in place.

    The FSM token (set in ``run_lg``) keeps stale buttons — and, in a group, taps from anyone
    other than the issuer — from firing, since FSM data is keyed per chat+user.
    由 FSM token 阻擋過期按鈕；群組中 FSM 以 chat+user 為鍵，故非發起者的點擊亦無效。
    """
    try:
        _, token, index_text = callback.data.split(":", 2)
        index = int(index_text)
    except ValueError:
        await callback.answer("Invalid selection.")
        return
    data = await state.get_data()
    if data.get("lg_token") != token:
        await callback.answer("This menu expired — re-run the command.", show_alert=True)
        return
    names = data.get("lg_agents", [])
    if not 0 <= index < len(names):
        await callback.answer("Invalid selection.")
        return
    agent = names[index]
    query_type = data["lg_query_type"]
    target = data["lg_target"]
    await callback.answer(f"Running {query_type} on {agent}…")
    await render_lg(
        callback.message,
        user_id=callback.from_user.id,
        query_type=query_type,
        target=target,
        agent=agent,
        names=names,
        token=token,
    )


@dp.message(Command("ping"), default_state)
async def ping_cmd(message: Message, state: FSMContext) -> None:
    await run_lg(message, state, "ping")


@dp.message(Command("trace", "mtr"), default_state)
async def trace_cmd(message: Message, state: FSMContext) -> None:
    await run_lg(message, state, "trace")


@dp.message(Command("route"), default_state)
async def route_cmd(message: Message, state: FSMContext) -> None:
    await run_lg(message, state, "route")


# --- Guided peer management ----------------------------------------------------------------
# Registered before the state-filtered step handlers so /cancel and the entry commands always
# take precedence over (and can restart) an active wizard.


@dp.message(Command("cancel"))
async def cancel_cmd(message: Message, state: FSMContext) -> None:
    if await state.get_state() is None:
        await message.answer("Nothing to cancel.", reply_markup=ReplyKeyboardRemove())
        return
    await state.clear()
    await message.answer("Cancelled.", reply_markup=ReplyKeyboardRemove())


@dp.message(Command("create"))
async def create_cmd(message: Message, state: FSMContext) -> None:
    await state.clear()
    # Confirm the account is verified before starting the wizard.
    verified = await call_backend(
        message,
        backend.get(f"/api/telegram/peer/{message.from_user.id}"),
        error_prefix="Could not start",
        not_found_message=NOT_LINKED_MSG,
    )
    if verified is None:
        return

    data = await call_backend(
        message,
        backend.get("/api/telegram/agents"),
        error_prefix="Could not load agents",
    )
    if data is None:
        return
    agents = data.get("agents", [])
    if not agents:
        await message.answer("No agents are available right now.")
        return
    await state.update_data(agents=[agent["name"] for agent in agents])
    await state.set_state(CreatePeer.agent)
    await message.answer(
        "Let's create a peer. Which PoP (agent)?", reply_markup=agent_keyboard(agents)
    )


@dp.message(Command("edit"))
async def edit_cmd(message: Message, state: FSMContext) -> None:
    await state.clear()
    peers = await load_user_peers(message)
    if peers is None:
        return
    if not peers:
        await message.answer("You have no peers to edit. Use /create first.")
        return
    await state.update_data(peer_ids=[p["id"] for p in peers])
    await state.set_state(EditPeer.choosing)
    await message.answer(
        "Which peer do you want to edit?\n" + peer_list_text(peers),
        reply_markup=peer_keyboard(peers),
    )


@dp.message(Command("delete"))
async def delete_cmd(message: Message, state: FSMContext) -> None:
    await state.clear()
    peers = await load_user_peers(message)
    if peers is None:
        return
    if not peers:
        await message.answer("You have no peers to delete.")
        return
    await state.update_data(peer_ids=[p["id"] for p in peers])
    await state.set_state(DeletePeer.choosing)
    await message.answer(
        "Which peer do you want to delete?\n" + peer_list_text(peers),
        reply_markup=peer_keyboard(peers),
    )


# Create wizard steps


@dp.message(CreatePeer.agent)
async def create_agent_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    choice = (message.text or "").strip()
    data = await state.get_data()
    if choice not in data.get("agents", []):
        await message.answer("Please pick one of the listed agents, or /cancel.")
        return
    await state.update_data(agent=choice)
    await state.set_state(CreatePeer.endpoint)
    await message.answer(
        "WireGuard endpoint as host:port (e.g. 198.51.100.7:51820).",
        reply_markup=ReplyKeyboardRemove(),
    )


@dp.message(CreatePeer.endpoint)
async def create_endpoint_step(message: Message, state: FSMContext) -> None:
    await handle_endpoint_step(
        message,
        state,
        action="create",
        next_state=CreatePeer.public_key,
        prompt="Your WireGuard public key (44-character base64).",
    )


@dp.message(CreatePeer.public_key)
async def create_key_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    key = (message.text or "").strip()
    if not WG_KEY_RE.match(key):
        await message.answer(
            "That doesn't look like a WireGuard public key (44-char base64 ending in '='). "
            "Try again or /cancel."
        )
        return
    data = await state.get_data()
    await state.clear()
    payload = {
        "telegram_user_id": str(message.from_user.id),
        "agent": data["agent"],
        "endpoint": data["endpoint"],
        "wg_public_key": key,
    }
    result = await call_backend(
        message,
        backend.post("/api/telegram/peer/create", payload),
        error_prefix="Create failed",
        reply_markup=ReplyKeyboardRemove(),
    )
    if result is None:
        return
    await send_peer_result(message, "Created", result)


# Edit wizard steps


@dp.message(EditPeer.choosing)
async def edit_choose_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "edit"):
        return
    peer_id = parse_peer_id(message.text)
    data = await state.get_data()
    if peer_id is None or peer_id not in data.get("peer_ids", []):
        await message.answer("Please pick one of your listed peers (e.g. #12), or /cancel.")
        return
    await state.update_data(peer_id=peer_id)
    await state.set_state(EditPeer.endpoint)
    await message.answer("New WireGuard endpoint as host:port.", reply_markup=ReplyKeyboardRemove())


@dp.message(EditPeer.endpoint)
async def edit_endpoint_step(message: Message, state: FSMContext) -> None:
    await handle_endpoint_step(
        message,
        state,
        action="edit",
        next_state=EditPeer.public_key,
        prompt="New WireGuard public key (44-character base64).",
    )


@dp.message(EditPeer.public_key)
async def edit_key_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "edit"):
        return
    key = (message.text or "").strip()
    if not WG_KEY_RE.match(key):
        await message.answer("That doesn't look like a WireGuard public key. Try again or /cancel.")
        return
    data = await state.get_data()
    await state.clear()
    payload = {
        "telegram_user_id": str(message.from_user.id),
        "peer_id": data["peer_id"],
        "endpoint": data["endpoint"],
        "wg_public_key": key,
    }
    result = await call_backend(
        message,
        backend.post("/api/telegram/peer/edit", payload),
        error_prefix="Edit failed",
        reply_markup=ReplyKeyboardRemove(),
    )
    if result is None:
        return
    await send_peer_result(message, "Updated", result)


# Delete wizard steps


@dp.message(DeletePeer.choosing)
async def delete_choose_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "delete"):
        return
    peer_id = parse_peer_id(message.text)
    data = await state.get_data()
    if peer_id is None or peer_id not in data.get("peer_ids", []):
        await message.answer("Please pick one of your listed peers (e.g. #12), or /cancel.")
        return
    await state.update_data(peer_id=peer_id)
    await state.set_state(DeletePeer.confirming)
    await message.answer(
        f"Delete peer #{peer_id}? This tears down the tunnel and BGP session. "
        "Send 'yes' to confirm, or /cancel.",
        reply_markup=ReplyKeyboardRemove(),
    )


@dp.message(DeletePeer.confirming)
async def delete_confirm_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "delete"):
        return
    if (message.text or "").strip().lower() not in {"yes", "y"}:
        await message.answer("Deletion not confirmed. Send 'yes' to confirm, or /cancel.")
        return
    data = await state.get_data()
    await state.clear()
    peer_id = data["peer_id"]
    deleted = await call_backend(
        message,
        backend.post(
            "/api/telegram/peer/delete",
            {"telegram_user_id": str(message.from_user.id), "peer_id": peer_id},
        ),
        error_prefix="Delete failed",
    )
    if deleted is None:
        return
    await message.answer(f"Deleted peer #{peer_id}.")


async def main() -> None:
    if not settings.telegram_bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")
    bot = Bot(settings.telegram_bot_token)
    try:
        await dp.start_polling(bot)
    finally:
        await backend.aclose()


if __name__ == "__main__":
    asyncio.run(main())
