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
    BotCommand,
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
from app.peer.validation import (
    DEFAULT_WIREGUARD_MTU,
    MAX_WIREGUARD_MTU,
    MIN_WIREGUARD_MTU,
    normalize_asn_number,
    normalize_wireguard_mtu,
)

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
    node = State()
    endpoint = State()
    public_key = State()
    dn42_ipv4 = State()
    dn42_ipv6 = State()
    link_local = State()
    mtu = State()
    bgp_extended = State()
    confirming = State()


class EditPeer(StatesGroup):
    choosing = State()
    endpoint = State()
    public_key = State()
    mtu = State()


class DeletePeer(StatesGroup):
    choosing = State()
    confirming = State()


def admin_asn_display() -> str:
    """The operator/admin ASN, formatted ``AS<number>`` (or a placeholder if unset/invalid).

    A Telegram user is granted admin rights when their verified ASN equals ``settings.local_asn``
    (see ``upsert_user_from_kioubit``), so that value *is* the admin ASN. ``LOCAL_ASN`` may be
    configured with or without an ``AS`` prefix, so normalise it for a consistent display.
    管理員 ASN 即 settings.local_asn:使用者通過驗證的 ASN 與其相同時才取得管理員權限。
    LOCAL_ASN 可能帶或不帶 AS 前綴,故正規化後統一以 AS<number> 顯示。
    """
    raw = settings.local_asn.strip()
    if not raw:
        return "(not configured)"
    try:
        return f"AS{normalize_asn_number(raw)}"
    except ValueError:
        return raw


HELP_TEXT = (
    "dn42 autopeer bot\n"
    f"Our ASN: {admin_asn_display()}\n\n"
    "/login - Login your dn42 ASN\n"
    "/logout - Logout your dn42 ASN\n"
    "/listpeers - Show your peers status\n"
    "/create - create a peer\n"
    "/edit - edit one of your peers\n"
    "/delete - delete one of your peers\n"
    "/ping\n"
    "/trace\n"
    "/mtr\n"
    "/route\n"
    "/cancel - Cancel ALL?"
)

# The command menu shown by Telegram's "/" picker, registered via set_my_commands on startup.
# Descriptions are the user-facing menu text. /start is intentionally omitted — it is the
# implicit front door (its handler is kept) — while /help is listed so the full command
# reference is reachable.
# Telegram「/」選單(啟動時以 set_my_commands 註冊)。/start 刻意省略(它是隱含的入口,handler 仍保留),
# /help 則列出以便取得完整指令說明。
BOT_COMMANDS = [
    BotCommand(command="login", description="Login your DN42 asn"),
    BotCommand(command="logout", description="Logout your DN42 asn"),
    BotCommand(command="listpeers", description="list your peers"),
    BotCommand(command="create", description="create your peer"),
    BotCommand(command="edit", description="edit a peer"),
    BotCommand(command="delete", description="delete a peer"),
    BotCommand(command="ping", description="ping someone"),
    BotCommand(command="trace", description="trace someone"),
    BotCommand(command="mtr", description="mtr someone"),
    BotCommand(command="route", description="show route on a node"),
    BotCommand(command="cancel", description="cancel all"),
    BotCommand(command="help", description="show this help"),
]


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


def parse_index(text: str | None, count: int) -> int | None:
    """Parse a 1-based selection index (``2`` or ``#2``), bounded to ``[1, count]``.

    Peers are picked by their position in the listed menu rather than by their UUID, so the user
    never has to type a long id. 以選單中的序號(而非 UUID)挑選對等,使用者無需輸入冗長的 id。"""
    if not text:
        return None
    cleaned = text.strip().lstrip("#").strip()
    if not cleaned.isdigit():
        return None
    index = int(cleaned)
    return index if 1 <= index <= count else None


def parse_mtu(text: str | None, *, allow_keep: bool = False) -> int | None:
    value = (text or "").strip().lower()
    if allow_keep and value in {"keep", "same"}:
        return None
    if value in {"", "default"}:
        return DEFAULT_WIREGUARD_MTU
    return normalize_wireguard_mtu(value)


def parse_optional_value(text: str | None) -> str:
    value = (text or "").strip()
    if value.lower() in {"", "skip", "none", "-"}:
        return ""
    return value


def parse_yes_no(text: str | None) -> bool | None:
    value = (text or "").strip().lower()
    if value in {"", "yes", "y", "on", "enable", "enabled", "true", "1", "default", "skip"}:
        return True
    if value in {"no", "n", "off", "disable", "disabled", "false", "0"}:
        return False
    return None


def peer_mtu(peer: dict) -> int:
    return int(peer.get("wg_mtu") or DEFAULT_WIREGUARD_MTU)


def peer_list_text(peers: list[dict]) -> str:
    lines = []
    for i, p in enumerate(peers, 1):
        endpoint = p.get("endpoint") or "no endpoint"
        lines.append(f"{i}. {p['node']} · {p['status']} · {endpoint} · mtu={peer_mtu(p)}")
    return "\n".join(lines)


def node_keyboard(nodes: list[dict]) -> ReplyKeyboardMarkup:
    rows = [[KeyboardButton(text=node["name"])] for node in nodes]
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=True)


def peer_keyboard(peers: list[dict]) -> ReplyKeyboardMarkup:
    # Buttons are the 1-based menu positions (see peer_list_text); the handler maps the picked
    # index back to the peer's UUID. 按鈕為選單序號,handler 再對應回對等的 UUID。
    rows = [[KeyboardButton(text=str(i))] for i, _ in enumerate(peers, 1)]
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=True)


def lg_node_inline_keyboard(
    node_names: list[str], token: str, active: str | None = None
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
        for index, name in enumerate(node_names)
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
    asn = info.get("asn", "")
    asn_display = f"AS{asn}" if asn and asn != "<our-asn>" else asn
    return (
        f"ASN: {asn_display}\n"
        f"IPv4: {info.get('ipv4') or '-'}\n"
        f"IPv6: {info.get('ipv6') or '-'}\n"
        f"Link-local: {info.get('link_local', '')}\n\n"
        f"Endpoint: {info.get('endpoint', '')}\n\n"
        f"WireGuard Public Key: {info.get('public_key', '')}\n"
        f"wireguard MTU: {info.get('mtu', DEFAULT_WIREGUARD_MTU)}"
    )


def peering_info_text(info: dict) -> str:
    """The our-side block shown after a successful deploy: a caption plus the parameters."""
    return "Use these settings to configure your interface:\n" + peering_info_lines(info)


def peer_preview_text(data: dict) -> str:
    peering = data.get("peering", {})
    return (
        "Review this peer before deployment.\n\n"
        "Interface helper:\n"
        f"{peering_info_lines(peering)}\n\n"
        "Your submitted details:\n"
        f"Node: {data.get('node', '')}\n"
        f"Endpoint: {data.get('endpoint') or '- (you dial us)'}\n"
        f"DN42 IPv4: {data.get('peer_dn42_ipv4') or '-'}\n"
        f"DN42 IPv6: {data.get('peer_dn42_ipv6') or '-'}\n"
        f"BGP neighbor address: {data.get('peer_link_address') or '-'}\n"
        f"BGP extensions: {'enabled' if data.get('bgp_extended') else 'disabled'}\n\n"
        "Send 'yes' to create it, or /cancel."
    )


async def send_peer_result(message: Message, action: str, result: dict) -> None:
    deploy_status = result.get("deploy_status")
    await message.answer(
        f"{action} peer on {result.get('node')} (AS{result.get('asn')}) — deploy: {deploy_status}",
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
    """Shared create/edit step: validate a host:port endpoint, or 'skip' for none, then advance."""
    if await reject_if_command(message, action):
        return
    endpoint = (message.text or "").strip()
    if endpoint.lower() in {"skip", "none", "-"}:
        endpoint = ""
    elif not looks_like_endpoint(endpoint):
        await message.answer(
            "Endpoint must be host:port (e.g. 198.51.100.7:51820), or send 'skip'. "
            "Try again or /cancel."
        )
        return
    await state.update_data(endpoint=endpoint)
    await state.set_state(next_state)
    await message.answer(prompt)


# --- Help & verification -------------------------------------------------------------------


@dp.message(Command("start", "help"), default_state)
async def help_cmd(message: Message) -> None:
    await message.answer(HELP_TEXT)


def findnoc_choice_keyboard(asns: list[str]) -> InlineKeyboardMarkup:
    """One button per ASN for the multi-ASN FindNOC case; the tapped ASN rides in callback_data."""
    rows = [[InlineKeyboardButton(text=asn, callback_data=f"fnlogin:{asn}")] for asn in asns]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def findnoc_success_text(data: dict) -> str:
    return (
        "Logged in via FindNOC quick verification.\n"
        f"ASN: AS{data['asn']}\n"
        "Your Telegram account is now linked. Use /create to add a peer."
    )


async def kioubit_login(message: Message) -> None:
    """Send the Kioubit Mini App verification button (original /login flow + FindNOC fallback).

    傳送 Kioubit Mini App 驗證按鈕:既是原本的 /login 流程,也是 FindNOC 無法使用時的回退。
    """
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


@dp.message(Command("login"), default_state)
async def login_cmd(message: Message) -> None:
    """Try FindNOC quick login first; fall back to the Kioubit Mini App when it can't be used.

    先試 FindNOC 快速登入(零額外操作);未註冊／未設定／上游故障時靜默回退到 Kioubit Mini App。
    """
    try:
        data = await backend.post(
            "/api/telegram/findnoc/login",
            {**user_payload(message), "username": message.from_user.username},
        )
    except httpx.HTTPStatusError as exc:
        # 404 = not in FindNOC, 503 = FindNOC off/unavailable → both fall back to Kioubit.
        if exc.response.status_code in (404, 503):
            await kioubit_login(message)
        else:
            await message.answer(f"Login failed: {detail_of(exc)}")
        return
    except httpx.HTTPError:
        # Backend unreachable; the Kioubit path needs it too, but follow the standard flow.
        await kioubit_login(message)
        return

    if data.get("need_choice"):
        await message.answer(
            "You control multiple ASNs in FindNOC — pick the one to log in with:",
            reply_markup=findnoc_choice_keyboard(data["asns"]),
        )
        return
    await message.answer(findnoc_success_text(data))


@dp.callback_query(F.data.startswith("fnlogin:"))
async def fnlogin_choose(callback: CallbackQuery) -> None:
    """Bind the ASN tapped from the multi-ASN FindNOC list; the backend re-verifies it."""
    asn = callback.data.split(":", 1)[1]
    try:
        data = await backend.post(
            "/api/telegram/findnoc/login",
            {
                "telegram_user_id": str(callback.from_user.id),
                "telegram_chat_id": str(callback.message.chat.id),
                "username": callback.from_user.username,
                "asn": asn,
            },
        )
    except httpx.HTTPStatusError as exc:
        await callback.answer()
        await callback.message.answer(f"Login failed: {detail_of(exc)}")
        return
    except httpx.HTTPError as exc:
        await callback.answer()
        await callback.message.answer(f"Login failed: {exc}")
        return
    await callback.answer("Verified")
    await callback.message.answer(findnoc_success_text(data))


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


@dp.message(Command("logout"), default_state)
async def logout_cmd(message: Message) -> None:
    result = await call_backend(
        message,
        backend.post("/api/telegram/logout", {"telegram_user_id": str(message.from_user.id)}),
        error_prefix="Logout failed",
        not_found_message=NOT_LINKED_MSG,
    )
    if result is None:
        return
    await message.answer(
        f"Logged out. Your Telegram account is no longer linked to AS{result.get('asn')}.\n"
        "Your peers are kept — use /login to link again."
    )


# --- Peer list & status --------------------------------------------------------------------


@dp.message(Command("listpeers"), default_state)
async def peers_cmd(message: Message) -> None:
    """List the caller's peers: one block per peer with its state, the our-side params to hand the
    other operator, and its live WireGuard + BGP status.

    每個對等一個區塊:狀態、提供對端的我方參數,以及即時 WireGuard 與 BGP 狀態。
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
        lines = [f"=== {peer['node']} (AS{peer['asn']}) [{label}] ==="]
        if peer.get("endpoint"):
            lines.append(f"your endpoint: {peer['endpoint']}")
        if peer.get("peer_dn42_ipv4"):
            lines.append(f"your DN42 IPv4: {peer['peer_dn42_ipv4']}")
        if peer.get("peer_dn42_ipv6"):
            lines.append(f"your DN42 IPv6: {peer['peer_dn42_ipv6']}")
        if peer.get("peer_link_address"):
            lines.append(f"your link-local: {peer['peer_link_address']}")
        lines.append(f"BGP extensions: {'enabled' if peer.get('bgp_extended') else 'disabled'}")
        if peer.get("peering"):
            lines.append(peering_info_lines(peer["peering"]))
        else:
            lines.append(f"wireguard MTU: {peer_mtu(peer)}")
        wg = str(peer.get("wg_detail", "")).strip() or "(no WireGuard status)"
        bird = str(peer.get("detail", "")).strip() or "(no detail)"
        blocks.append("\n".join(lines) + f"\n\n[WireGuard]\n{wg}\n\n[BIRD]\n{bird}")
    for chunk in chunk_blocks(blocks):
        await message.answer(f"```\n{chunk}\n```", parse_mode="Markdown")


# --- Looking glass -------------------------------------------------------------------------


def parse_lg_target(message: Message) -> str:
    """Pull the single target out of ``/<command> <target>``.

    The node is chosen from the inline buttons attached to the reply, not as a positional
    argument, so any extra tokens are ignored. 節點改由內嵌按鈕選擇,因此會忽略多餘的 token。
    """
    parts = (message.text or "").split()
    if len(parts) < 2:
        raise ValueError("Usage: /<command> <target>")
    return parts[1]


def lg_caption(query_type: str, target: str) -> str:
    """The ``<type> <target>`` heading shown above looking-glass output."""
    return f"{query_type} {target}".rstrip()


async def run_lg(message: Message, state: FSMContext, query_type: str) -> None:
    """Run the query on a random node immediately, then let the user switch nodes via buttons.

    立即在隨機節點上執行,並附按鈕讓使用者切換節點(結果就地以 edit 更新)。
    """
    try:
        target = parse_lg_target(message)
    except ValueError as exc:
        await message.answer(str(exc))
        return
    data = await call_backend(
        message,
        backend.get("/api/telegram/nodes"),
        error_prefix="Could not load nodes",
    )
    if data is None:
        return
    names = [node["name"] for node in data.get("nodes", [])]
    if not names:
        await message.answer("No nodes are available right now.")
        return
    # A fresh token per command so a tap only runs against the query it was shown with; a newer
    # /ping|/trace|/route overwrites it, expiring the previous message's buttons (see lg_choose).
    token = secrets.token_urlsafe(6)
    await state.update_data(
        lg_token=token, lg_query_type=query_type, lg_target=target, lg_nodes=names
    )
    # Pick a random node and show output right away; the user can switch via the buttons.
    node = random.choice(names)
    placeholder = await message.answer(
        format_block(f"{lg_caption(query_type, target)} @ {node}\n\nrunning…"),
        parse_mode="Markdown",
        reply_markup=lg_node_inline_keyboard(names, token, active=node),
    )
    await render_lg(
        placeholder,
        user_id=message.from_user.id,
        query_type=query_type,
        target=target,
        node=node,
        names=names,
        token=token,
    )


async def render_lg(
    message: Message,
    *,
    user_id: int,
    query_type: str,
    target: str,
    node: str,
    names: list[str],
    token: str,
) -> None:
    """Run one looking-glass query and edit ``message`` in place with the labelled output.

    The keyboard is re-attached (``node`` marked) so the user can keep switching nodes on the
    same message; an HTTP error is shown in the block rather than as a separate message.
    """
    try:
        result = await backend.post(
            "/api/telegram/lg",
            {
                "telegram_user_id": str(user_id),
                "node": node,
                "query_type": query_type,
                "target": target,
            },
        )
        body = str(result.get("output", result))
    except httpx.HTTPStatusError as exc:
        body = f"Looking glass failed: {detail_of(exc)}"
    except httpx.HTTPError as exc:
        body = f"Looking glass failed: {exc}"
    text = format_block(f"{lg_caption(query_type, target)} @ {node}\n\n{body}")
    try:
        await message.edit_text(
            text,
            parse_mode="Markdown",
            reply_markup=lg_node_inline_keyboard(names, token, active=node),
        )
    except TelegramBadRequest:
        # e.g. "message is not modified" when the same node is tapped twice with identical output.
        pass


@dp.callback_query(F.data.startswith("lg:"))
async def lg_choose(callback: CallbackQuery, state: FSMContext) -> None:
    """Re-run the query on the tapped node and edit the message output in place.

    The FSM token (set in ``run_lg``) keeps stale buttons — and, in a group, taps from anyone
    other than the issuer — from firing, since FSM data is keyed per chat+user.
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
    names = data.get("lg_nodes", [])
    if not 0 <= index < len(names):
        await callback.answer("Invalid selection.")
        return
    node = names[index]
    query_type = data["lg_query_type"]
    target = data["lg_target"]
    await callback.answer(f"Running {query_type} on {node}…")
    await render_lg(
        callback.message,
        user_id=callback.from_user.id,
        query_type=query_type,
        target=target,
        node=node,
        names=names,
        token=token,
    )


@dp.message(Command("ping"), default_state)
async def ping_cmd(message: Message, state: FSMContext) -> None:
    await run_lg(message, state, "ping")


@dp.message(Command("trace"), default_state)
async def trace_cmd(message: Message, state: FSMContext) -> None:
    await run_lg(message, state, "trace")


@dp.message(Command("mtr"), default_state)
async def mtr_cmd(message: Message, state: FSMContext) -> None:
    await run_lg(message, state, "mtr")


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
        backend.get("/api/telegram/nodes"),
        error_prefix="Could not load nodes",
    )
    if data is None:
        return
    nodes = data.get("nodes", [])
    if not nodes:
        await message.answer("No nodes are available right now.")
        return
    await state.update_data(nodes=[node["name"] for node in nodes])
    await state.set_state(CreatePeer.node)
    await message.answer("Let's create a peer. Which node?", reply_markup=node_keyboard(nodes))


@dp.message(Command("edit"))
async def edit_cmd(message: Message, state: FSMContext) -> None:
    await state.clear()
    peers = await load_user_peers(message)
    if peers is None:
        return
    if not peers:
        await message.answer("You have no peers to edit. Use /create first.")
        return
    await state.update_data(
        peer_ids=[p["id"] for p in peers],
        peer_mtu={str(p["id"]): peer_mtu(p) for p in peers},
    )
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


@dp.message(CreatePeer.node)
async def create_node_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    choice = (message.text or "").strip()
    data = await state.get_data()
    if choice not in data.get("nodes", []):
        await message.answer("Please pick one of the listed nodes, or /cancel.")
        return
    await state.update_data(node=choice)
    await state.set_state(CreatePeer.endpoint)
    await message.answer(
        "WireGuard endpoint as host:port (e.g. 198.51.100.7:51820), "
        "or send 'skip' if your side will dial us.",
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
    await state.update_data(wg_public_key=key)
    await state.set_state(CreatePeer.dn42_ipv4)
    await message.answer("Your DN42 IPv4 address, or send 'skip'.")


@dp.message(CreatePeer.dn42_ipv4)
async def create_dn42_ipv4_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    await state.update_data(peer_dn42_ipv4=parse_optional_value(message.text))
    await state.set_state(CreatePeer.dn42_ipv6)
    await message.answer("Your DN42 IPv6 address, or send 'skip'.")


@dp.message(CreatePeer.dn42_ipv6)
async def create_dn42_ipv6_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    await state.update_data(peer_dn42_ipv6=parse_optional_value(message.text))
    await state.set_state(CreatePeer.link_local)
    await message.answer("Your link-local/BGP address (e.g. fe80::99), or send 'skip'.")


@dp.message(CreatePeer.link_local)
async def create_link_local_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    await state.update_data(peer_link_address=parse_optional_value(message.text))
    await state.set_state(CreatePeer.mtu)
    await message.answer(
        f"WireGuard MTU ({MIN_WIREGUARD_MTU}-{MAX_WIREGUARD_MTU}). "
        f"Send 'default' to use {DEFAULT_WIREGUARD_MTU}."
    )


@dp.message(CreatePeer.mtu)
async def create_mtu_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    try:
        mtu = parse_mtu(message.text)
    except ValueError as exc:
        await message.answer(f"{exc}. Try again or /cancel.")
        return
    await state.update_data(wg_mtu=mtu)
    await state.set_state(CreatePeer.bgp_extended)
    await message.answer(
        "Enable BGP extensions (multiprotocol BGP, extended nexthop)? "
        "Send yes/no, or default for yes."
    )


@dp.message(CreatePeer.bgp_extended)
async def create_bgp_extended_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    bgp_extended = parse_yes_no(message.text)
    if bgp_extended is None:
        await message.answer("Please send yes or no, or /cancel.")
        return
    await state.update_data(bgp_extended=bgp_extended)
    data = await state.get_data()
    payload = {
        "telegram_user_id": str(message.from_user.id),
        "node": data["node"],
        "endpoint": data["endpoint"],
        "wg_public_key": data["wg_public_key"],
        "peer_dn42_ipv4": data.get("peer_dn42_ipv4", ""),
        "peer_dn42_ipv6": data.get("peer_dn42_ipv6", ""),
        "peer_link_address": data.get("peer_link_address", ""),
        "wg_mtu": data["wg_mtu"],
        "bgp_extended": data["bgp_extended"],
    }
    preview = await call_backend(
        message,
        backend.post("/api/telegram/peer/preview", payload),
        error_prefix="Preview failed",
        reply_markup=ReplyKeyboardRemove(),
    )
    if preview is None:
        return
    await state.update_data(create_payload=payload)
    await state.set_state(CreatePeer.confirming)
    await message.answer(format_block(peer_preview_text(preview)), parse_mode="Markdown")


@dp.message(CreatePeer.confirming)
async def create_confirm_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "create"):
        return
    if (message.text or "").strip().lower() not in {"yes", "y"}:
        await message.answer("Not confirmed. Send 'yes' to create it, or /cancel.")
        return
    data = await state.get_data()
    await state.clear()
    result = await call_backend(
        message,
        backend.post("/api/telegram/peer/create", data["create_payload"]),
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
    data = await state.get_data()
    peer_ids = data.get("peer_ids", [])
    index = parse_index(message.text, len(peer_ids))
    if index is None:
        await message.answer("Reply with the number of a listed peer, or /cancel.")
        return
    await state.update_data(peer_id=peer_ids[index - 1])
    await state.set_state(EditPeer.endpoint)
    await message.answer(
        "New WireGuard endpoint as host:port, or send 'skip' for none.",
        reply_markup=ReplyKeyboardRemove(),
    )


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
    await state.update_data(wg_public_key=key)
    data = await state.get_data()
    current_mtu = data.get("peer_mtu", {}).get(str(data["peer_id"]), DEFAULT_WIREGUARD_MTU)
    await state.set_state(EditPeer.mtu)
    await message.answer(
        f"New WireGuard MTU ({MIN_WIREGUARD_MTU}-{MAX_WIREGUARD_MTU}, "
        f"current {current_mtu}). Send 'keep' to keep it."
    )


@dp.message(EditPeer.mtu)
async def edit_mtu_step(message: Message, state: FSMContext) -> None:
    if await reject_if_command(message, "edit"):
        return
    try:
        mtu = parse_mtu(message.text, allow_keep=True)
    except ValueError as exc:
        await message.answer(f"{exc}. Try again, send 'keep', or /cancel.")
        return
    data = await state.get_data()
    await state.clear()
    payload = {
        "telegram_user_id": str(message.from_user.id),
        "peer_id": data["peer_id"],
        "endpoint": data["endpoint"],
        "wg_public_key": data["wg_public_key"],
        "wg_mtu": mtu,
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
    data = await state.get_data()
    peer_ids = data.get("peer_ids", [])
    index = parse_index(message.text, len(peer_ids))
    if index is None:
        await message.answer("Reply with the number of a listed peer, or /cancel.")
        return
    await state.update_data(peer_id=peer_ids[index - 1])
    await state.set_state(DeletePeer.confirming)
    await message.answer(
        "Delete this peer? This tears down the tunnel and BGP session. "
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
    await message.answer("Deleted peer.")


async def main() -> None:
    if not settings.telegram_bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")
    bot = Bot(settings.telegram_bot_token)
    try:
        # Register the "/" command menu so Telegram clients advertise exactly this command set.
        # 註冊「/」指令選單,使 Telegram 用戶端顯示的指令集與此完全一致。
        await bot.set_my_commands(BOT_COMMANDS)
        await dp.start_polling(bot)
    finally:
        await backend.aclose()


if __name__ == "__main__":
    asyncio.run(main())
