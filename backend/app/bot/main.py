import asyncio
import json
from typing import Any

import httpx
from aiogram import Bot, Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
    WebAppInfo,
)

from app.config import get_settings


settings = get_settings()


class Backend:
    def __init__(self) -> None:
        self.base_url = settings.base_url.rstrip("/")
        self.headers = {"X-Backend-Secret": settings.telegram_backend_secret}

    async def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                f"{self.base_url}{path}",
                json=payload,
                headers=self.headers,
            )
        response.raise_for_status()
        return response.json()

    async def get(self, path: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(f"{self.base_url}{path}", headers=self.headers)
        response.raise_for_status()
        return response.json()


backend = Backend()
dp = Dispatcher()


def user_payload(message: Message) -> dict[str, str]:
    return {
        "telegram_user_id": str(message.from_user.id),
        "telegram_chat_id": str(message.chat.id),
    }


@dp.message(Command("start", "help"))
async def help_cmd(message: Message) -> None:
    await message.answer(
        "dn42 autopeer bot\n\n"
        "/verify - link your dn42 ASN\n"
        "/peer - show your peers\n"
        "/status [agent] - show agent status\n"
        "/ping <dn42-ip> [agent]\n"
        "/mtr <dn42-ip> [agent]\n"
        "/route <dn42-prefix|dn42-ip> [agent]"
    )


@dp.message(Command("verify", "login"))
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


@dp.message(Command("peer"))
async def peer_cmd(message: Message) -> None:
    try:
        result = await backend.get(f"/api/telegram/peer/{message.from_user.id}")
    except httpx.HTTPStatusError as exc:
        await message.answer(f"Peer lookup failed: {exc.response.text}")
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Peer lookup failed: {exc}")
        return

    if not result["peers"]:
        await message.answer(f"AS{result['asn']} has no peers yet.")
        return
    lines = [f"AS{result['asn']} peers:"]
    for peer in result["peers"]:
        lines.append(f"#{peer['id']} {peer['agent']} {peer['status']} {peer['endpoint']}")
    await message.answer("\n".join(lines))


def parse_lg_args(message: Message, default_query: str) -> tuple[str, str, str]:
    parts = (message.text or "").split()
    if default_query == "status":
        agent = parts[1] if len(parts) > 1 else "local"
        return default_query, "", agent
    if len(parts) < 2:
        raise ValueError("Missing target")
    target = parts[1]
    agent = parts[2] if len(parts) > 2 else "local"
    return default_query, target, agent


async def run_lg(message: Message, query_type: str) -> None:
    try:
        query_type, target, agent = parse_lg_args(message, query_type)
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
        await message.answer(f"Looking glass failed: {exc.response.text}")
        return
    except httpx.HTTPError as exc:
        await message.answer(f"Looking glass failed: {exc}")
        return

    output = str(result.get("output", result))
    if len(output) > 3900:
        output = output[:3900] + "\n...[truncated]"
    await message.answer(f"```\n{output}\n```", parse_mode="Markdown")


@dp.message(Command("ping"))
async def ping_cmd(message: Message) -> None:
    await run_lg(message, "ping")


@dp.message(Command("mtr"))
async def mtr_cmd(message: Message) -> None:
    await run_lg(message, "mtr")


@dp.message(Command("route"))
async def route_cmd(message: Message) -> None:
    await run_lg(message, "route")


@dp.message(Command("status"))
async def status_cmd(message: Message) -> None:
    await run_lg(message, "status")


async def main() -> None:
    if not settings.telegram_bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")
    bot = Bot(settings.telegram_bot_token)
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
