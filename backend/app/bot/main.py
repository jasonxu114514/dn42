import asyncio
import json
import re
from typing import Any

import httpx
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup, default_state
from aiogram.types import (
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
    ReplyKeyboardRemove,
    WebAppInfo,
)

from app.config import get_settings


settings = get_settings()

WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")


class Backend:
    def __init__(self) -> None:
        self.base_url = settings.bot_backend_url.rstrip("/")
        self.headers = {"X-Backend-Secret": settings.telegram_backend_secret}

    async def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=40) as client:
            response = await client.post(
                f"{self.base_url}{path}",
                json=payload,
                headers=self.headers,
            )
        response.raise_for_status()
        return response.json()

    async def get(self, path: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(f"{self.base_url}{path}", headers=self.headers)
        response.raise_for_status()
        return response.json()


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
    "/peer - list your peers\n"
    "/status - detailed BGP status of your peers\n"
    "/create - create a peer (guided)\n"
    "/edit - edit one of your peers (guided)\n"
    "/delete - delete one of your peers (guided)\n"
    "/ping <dn42-ip> [agent]\n"
    "/trace <dn42-ip> [agent]\n"
    "/route <dn42-prefix|dn42-ip> [agent]\n"
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
    return "\n".join(
        f"#{p['id']} {p['agent']} {p['status']} {p['endpoint']}" for p in peers
    )


def agent_keyboard(agents: list[dict]) -> ReplyKeyboardMarkup:
    rows = [[KeyboardButton(text=agent["name"])] for agent in agents]
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=True)


def peer_keyboard(peers: list[dict]) -> ReplyKeyboardMarkup:
    rows = [[KeyboardButton(text=f"#{p['id']}")] for p in peers]
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=True)


async def reject_if_command(message: Message, action: str) -> bool:
    """Stop a stray slash-command from being stored as a wizard field value."""
    if message.text and message.text.strip().startswith("/"):
        await message.answer(f"You're in the middle of /{action}. Send /cancel to abort.")
        return True
    return False


async def load_user_peers(message: Message) -> list[dict] | None:
    """Return the caller's peers, or None after answering with the reason (unverified / error)."""
    try:
        data = await backend.get(f"/api/telegram/peer/{message.from_user.id}")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            await message.answer("Your Telegram account is not linked to a dn42 ASN yet. Use /login first.")
        else:
            await message.answer(f"Could not load your peers: {detail_of(exc)}")
        return None
    except httpx.HTTPError as exc:
        await message.answer(f"Could not load your peers: {exc}")
        return None
    return data.get("peers", [])


async def send_peer_result(message: Message, action: str, result: dict) -> None:
    await message.answer(
        f"{action} peer #{result.get('id')} on {result.get('agent')} "
        f"(AS{result.get('asn')}) — deploy: {result.get('deploy_status')}",
        reply_markup=ReplyKeyboardRemove(),
    )
    output = str(result.get("deploy_output", "")).strip()
    if output:
        await message.answer(format_block(output, 1500), parse_mode="Markdown")


# --- Help & verification -------------------------------------------------------------------


@dp.message(Command("start", "help"), default_state)
async def help_cmd(message: Message) -> None:
    await message.answer(HELP_TEXT)


@dp.message(Command("verify", "login"), default_state)
async def verify_cmd(message: Message) -> None:
    try:
        data = await backend.post("/api/telegram/challenge", user_payload(message))
    except httpx.HTTPError as exc:
        await message.answer(f"Could not create verification challenge: {exc}")
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
        result = await backend.post("/api/telegram/verify", payload)
    except (KeyError, json.JSONDecodeError) as exc:
        await message.answer(f"Verification data was malformed: {exc}")
        return
    except httpx.HTTPStatusError as exc:
        await message.answer(f"Verification failed: {exc.response.text}")
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Verification failed: {exc}")
        return

    await message.answer(
        "ASN verification complete.\n"
        f"ASN: AS{result['asn']}\n"
        f"Maintainer: {result.get('effective_mnt') or 'unknown'}\n"
        f"Method: {result.get('authtype') or 'unknown'}"
    )


# --- Peer list & status --------------------------------------------------------------------


@dp.message(Command("peer"), default_state)
async def peer_cmd(message: Message) -> None:
    peers = await load_user_peers(message)
    if peers is None:
        return
    if not peers:
        await message.answer("You have no peers yet. Use /create to add one.")
        return
    await message.answer("Your peers:\n" + peer_list_text(peers))


@dp.message(Command("status"), default_state)
async def status_cmd(message: Message) -> None:
    try:
        result = await backend.post(
            "/api/telegram/status", {"telegram_user_id": str(message.from_user.id)}
        )
    except httpx.HTTPStatusError as exc:
        await message.answer(f"Status lookup failed: {detail_of(exc)}")
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Status lookup failed: {exc}")
        return

    peers = result.get("peers", [])
    if not peers:
        await message.answer(f"AS{result.get('asn')} has no peers yet.")
        return
    blocks = []
    for peer in peers:
        header = f"=== #{peer['id']} {peer['agent']} (AS{peer['asn']}) [{peer['deploy_status']}] ==="
        body = str(peer.get("detail", "")).strip() or "(no detail)"
        blocks.append(f"{header}\n{body}")
    for chunk in chunk_blocks(blocks):
        await message.answer(f"```\n{chunk}\n```", parse_mode="Markdown")


# --- Looking glass -------------------------------------------------------------------------


def parse_lg_args(message: Message) -> tuple[str, str]:
    parts = (message.text or "").split()
    if len(parts) < 2:
        raise ValueError("Usage: /<command> <dn42-ip-or-prefix> [agent]")
    target = parts[1]
    agent = parts[2] if len(parts) > 2 else "local"
    return target, agent


async def run_lg(message: Message, query_type: str) -> None:
    try:
        target, agent = parse_lg_args(message)
        result = await backend.post(
            "/api/telegram/lg",
            {
                "telegram_user_id": str(message.from_user.id),
                "agent": agent,
                "query_type": query_type,
                "target": target,
            },
        )
    except ValueError as exc:
        await message.answer(str(exc))
        return
    except httpx.HTTPStatusError as exc:
        await message.answer(f"Looking glass failed: {detail_of(exc)}")
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Looking glass failed: {exc}")
        return

    await message.answer(format_block(str(result.get("output", result))), parse_mode="Markdown")


@dp.message(Command("ping"), default_state)
async def ping_cmd(message: Message) -> None:
    await run_lg(message, "ping")


@dp.message(Command("trace", "mtr"), default_state)
async def trace_cmd(message: Message) -> None:
    await run_lg(message, "trace")


@dp.message(Command("route"), default_state)
async def route_cmd(message: Message) -> None:
    await run_lg(message, "route")


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
    try:
        await backend.get(f"/api/telegram/peer/{message.from_user.id}")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            await message.answer("Your Telegram account is not linked to a dn42 ASN yet. Use /login first.")
        else:
            await message.answer(f"Could not start: {detail_of(exc)}")
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Could not start: {exc}")
        return

    try:
        data = await backend.get("/api/telegram/agents")
    except httpx.HTTPError as exc:
        await message.answer(f"Could not load agents: {exc}")
        return
    agents = data.get("agents", [])
    if not agents:
        await message.answer("No agents are available right now.")
        return
    await state.update_data(agents=[agent["name"] for agent in agents])
    await state.set_state(CreatePeer.agent)
    await message.answer("Let's create a peer. Which PoP (agent)?", reply_markup=agent_keyboard(agents))


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
    await message.answer("Which peer do you want to edit?\n" + peer_list_text(peers), reply_markup=peer_keyboard(peers))


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
    await message.answer("Which peer do you want to delete?\n" + peer_list_text(peers), reply_markup=peer_keyboard(peers))


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
    if await reject_if_command(message, "create"):
        return
    endpoint = (message.text or "").strip()
    if not looks_like_endpoint(endpoint):
        await message.answer("Endpoint must be host:port (e.g. 198.51.100.7:51820). Try again or /cancel.")
        return
    await state.update_data(endpoint=endpoint)
    await state.set_state(CreatePeer.public_key)
    await message.answer("Your WireGuard public key (44-character base64).")


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
    try:
        result = await backend.post("/api/telegram/peer/create", payload)
    except httpx.HTTPStatusError as exc:
        await message.answer(f"Create failed: {detail_of(exc)}", reply_markup=ReplyKeyboardRemove())
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Create failed: {exc}", reply_markup=ReplyKeyboardRemove())
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
    if await reject_if_command(message, "edit"):
        return
    endpoint = (message.text or "").strip()
    if not looks_like_endpoint(endpoint):
        await message.answer("Endpoint must be host:port (e.g. 198.51.100.7:51820). Try again or /cancel.")
        return
    await state.update_data(endpoint=endpoint)
    await state.set_state(EditPeer.public_key)
    await message.answer("New WireGuard public key (44-character base64).")


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
    try:
        result = await backend.post("/api/telegram/peer/edit", payload)
    except httpx.HTTPStatusError as exc:
        await message.answer(f"Edit failed: {detail_of(exc)}", reply_markup=ReplyKeyboardRemove())
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Edit failed: {exc}", reply_markup=ReplyKeyboardRemove())
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
    try:
        await backend.post(
            "/api/telegram/peer/delete",
            {"telegram_user_id": str(message.from_user.id), "peer_id": peer_id},
        )
    except httpx.HTTPStatusError as exc:
        await message.answer(f"Delete failed: {detail_of(exc)}")
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Delete failed: {exc}")
        return
    await message.answer(f"Deleted peer #{peer_id}.")


async def main() -> None:
    if not settings.telegram_bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")
    bot = Bot(settings.telegram_bot_token)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
