from __future__ import annotations

import asyncio
import json
import logging
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from threading import RLock
from typing import Any

import anyio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from app.db.models import Agent, utcnow
from app.db.session import SessionLocal
from app.peer.validation import normalize_wireguard_key

logger = logging.getLogger("dn42.autopeer")
router = APIRouter()
MAX_STATUS_OUTPUT = 65536


class AgentOfflineError(RuntimeError):
    pass


class AgentRequestError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentAuth:
    id: int
    name: str


@dataclass
class AgentRuntime:
    online: bool = False
    connected_at: datetime | None = None
    last_seen_at: datetime | None = None
    system: dict[str, Any] = field(default_factory=dict)


class AgentConnection:
    def __init__(self, websocket: WebSocket, agent: AgentAuth) -> None:
        self.websocket = websocket
        self.agent = agent
        self.pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
        self.send_lock = asyncio.Lock()

    async def send_json(self, payload: dict[str, Any]) -> None:
        async with self.send_lock:
            await self.websocket.send_json(payload)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.websocket.application_state == WebSocketState.CONNECTED:
            try:
                await self.websocket.close(code=code, reason=reason)
            except RuntimeError:
                pass

    def fail_pending(self, exc: Exception) -> None:
        for future in list(self.pending.values()):
            if not future.done():
                future.set_exception(exc)
        self.pending.clear()


class AgentHub:
    def __init__(self) -> None:
        self._connections: dict[int, AgentConnection] = {}
        self._runtime: dict[int, AgentRuntime] = {}
        self._lock = RLock()

    async def register(self, websocket: WebSocket, agent: AgentAuth) -> AgentConnection:
        connection = AgentConnection(websocket, agent)
        previous: AgentConnection | None = None
        now = utcnow()
        with self._lock:
            previous = self._connections.get(agent.id)
            self._connections[agent.id] = connection
            state = self._runtime.setdefault(agent.id, AgentRuntime())
            state.online = True
            state.connected_at = now
            state.last_seen_at = now
        if previous is not None:
            previous.fail_pending(AgentOfflineError(f"Agent '{agent.name}' reconnected"))
            await previous.close(code=4000, reason="replaced by a newer connection")
        _store_agent_status(agent.id, system=None, public_key=None)
        logger.info("Agent %s connected over websocket", agent.name)
        return connection

    async def unregister(self, connection: AgentConnection) -> None:
        with self._lock:
            current = self._connections.get(connection.agent.id)
            if current is not connection:
                return
            self._connections.pop(connection.agent.id, None)
            state = self._runtime.setdefault(connection.agent.id, AgentRuntime())
            state.online = False
        connection.fail_pending(AgentOfflineError(f"Agent '{connection.agent.name}' disconnected"))
        logger.info("Agent %s disconnected from websocket", connection.agent.name)

    async def request(
        self,
        agent: Agent,
        command: str,
        payload: dict[str, Any] | None,
        timeout: float,
    ) -> dict[str, Any]:
        if not agent.enabled:
            raise ValueError("Agent is disabled")
        with self._lock:
            connection = self._connections.get(agent.id)
        if connection is None:
            raise AgentOfflineError(f"Agent '{agent.name}' is offline")

        request_id = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        future: asyncio.Future[dict[str, Any]] = loop.create_future()
        connection.pending[request_id] = future
        try:
            await connection.send_json(
                {
                    "type": "request",
                    "id": request_id,
                    "command": command,
                    "payload": payload or {},
                }
            )
            response = await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError as exc:
            raise AgentRequestError(f"Agent '{agent.name}' timed out running {command}") from exc
        except AgentOfflineError:
            raise
        except Exception as exc:
            raise AgentOfflineError(f"Agent '{agent.name}' connection failed: {exc}") from exc
        finally:
            connection.pending.pop(request_id, None)

        error = response.get("error")
        if error:
            raise AgentRequestError(str(error))
        result = response.get("result")
        if not isinstance(result, dict):
            raise AgentRequestError("Agent returned an invalid response")
        self._mark_online(connection)
        return result

    async def handle_message(self, connection: AgentConnection, message: dict[str, Any]) -> None:
        message_type = message.get("type")
        if message_type == "response":
            request_id = str(message.get("id") or "")
            future = connection.pending.get(request_id)
            if future is not None and not future.done():
                future.set_result(message)
            return
        if message_type in {"hello", "heartbeat"}:
            system = _clean_system_status(message.get("system"))
            public_key = message.get("public_key")
            await self.record_seen(
                connection,
                system=system,
                public_key=public_key if isinstance(public_key, str) else None,
            )
            return
        logger.debug("Ignoring websocket message from agent %s: %r", connection.agent.name, message)

    def _mark_online(
        self,
        connection: AgentConnection,
        system: dict[str, Any] | None = None,
    ) -> bool:
        """Refresh in-memory liveness for a still-current connection, returning False once it has
        been replaced. No DB I/O: this runs on the command hot path, so persistence is left to the
        periodic heartbeat (see record_seen)."""
        now = utcnow()
        with self._lock:
            if self._connections.get(connection.agent.id) is not connection:
                return False
            state = self._runtime.setdefault(connection.agent.id, AgentRuntime())
            state.online = True
            state.last_seen_at = now
            if system:
                state.system = system
        return True

    async def record_seen(
        self,
        connection: AgentConnection,
        *,
        system: dict[str, Any] | None,
        public_key: str | None,
    ) -> None:
        if self._mark_online(connection, system):
            _store_agent_status(connection.agent.id, system=system, public_key=public_key)

    def snapshot(self) -> dict[int, AgentRuntime]:
        with self._lock:
            return {
                agent_id: AgentRuntime(
                    online=state.online,
                    connected_at=state.connected_at,
                    last_seen_at=state.last_seen_at,
                    system=dict(state.system),
                )
                for agent_id, state in self._runtime.items()
            }


agent_hub = AgentHub()


async def request_agent(
    agent: Agent,
    command: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    return await agent_hub.request(agent, command, payload, timeout)


def request_agent_sync(
    agent: Agent,
    command: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    try:
        return anyio.from_thread.run(request_agent, agent, command, payload, timeout)
    except RuntimeError as exc:
        message = str(exc)
        if "AnyIO worker thread" not in message and "can only be run from" not in message:
            raise
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(request_agent(agent, command, payload, timeout))
        raise


@router.websocket("/api/agents/ws")
async def agent_websocket(websocket: WebSocket) -> None:
    agent = _authenticate_agent(websocket)
    if agent is None:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    connection = await agent_hub.register(websocket, agent)
    try:
        while True:
            message = await websocket.receive_json()
            if isinstance(message, dict):
                await agent_hub.handle_message(connection, message)
            else:
                logger.debug("Ignoring non-object websocket message from agent %s", agent.name)
    except WebSocketDisconnect:
        pass
    except ValueError as exc:
        logger.warning("Invalid websocket JSON from agent %s: %s", agent.name, exc)
    finally:
        await agent_hub.unregister(connection)


def agent_runtime_context(agents: list[Agent]) -> dict[int, dict[str, Any]]:
    live = agent_hub.snapshot()
    context: dict[int, dict[str, Any]] = {}
    for agent in agents:
        state = live.get(agent.id)
        stored_system = _load_system_status(agent.system_status_json)
        system = state.system if state and state.system else stored_system
        last_seen_at = state.last_seen_at if state and state.last_seen_at else agent.last_seen_at
        context[agent.id] = {
            "online": bool(state and state.online),
            "connected_at": state.connected_at if state else None,
            "last_seen_at": last_seen_at,
            "system": system,
            "system_summary": _system_summary(system),
            "resource_metrics": _resource_metrics(system),
        }
    return context


def _authenticate_agent(websocket: WebSocket) -> AgentAuth | None:
    name = websocket.query_params.get("name", "").strip()
    if not name:
        return None
    token = _bearer_token(websocket.headers.get("authorization", ""))
    with SessionLocal() as db:
        agent = db.query(Agent).filter(Agent.name == name).one_or_none()
        if agent is None or not agent.enabled:
            return None
        if agent.token and not secrets.compare_digest(token, agent.token):
            return None
        if not agent.token and token:
            return None
        return AgentAuth(id=agent.id, name=agent.name)


def _bearer_token(header: str) -> str:
    prefix = "Bearer "
    if header.startswith(prefix):
        return header[len(prefix) :]
    return ""


def _store_agent_status(
    agent_id: int,
    *,
    system: dict[str, Any] | None,
    public_key: str | None,
) -> None:
    with SessionLocal() as db:
        agent = db.query(Agent).filter(Agent.id == agent_id).one_or_none()
        if agent is None:
            return
        agent.last_seen_at = utcnow()
        if system:
            agent.system_status_json = json.dumps(system, sort_keys=True, separators=(",", ":"))
        if public_key:
            try:
                agent.wg_public_key = normalize_wireguard_key(public_key)
            except ValueError:
                logger.warning("Agent %s sent an invalid WireGuard public key", agent.name)
        db.commit()


def _clean_system_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    cleaned: dict[str, Any] = {}
    for key in ("hostname", "os", "arch"):
        item = value.get(key)
        if isinstance(item, str) and item.strip():
            cleaned[key] = item.strip()[:128]
    for key in ("uptime_seconds", "goroutines"):
        item = value.get(key)
        if isinstance(item, (int, float)):
            cleaned[key] = int(item)
    for key in (
        "load_1",
        "load_5",
        "load_15",
        "cpu_percent",
        "memory_percent",
        "network_rx_bytes_per_second",
        "network_tx_bytes_per_second",
    ):
        item = value.get(key)
        if isinstance(item, (int, float)):
            cleaned[key] = round(max(float(item), 0.0), 2)
    for key in ("memory_used_bytes", "memory_total_bytes"):
        item = value.get(key)
        if isinstance(item, (int, float)):
            cleaned[key] = max(int(item), 0)
    for key in ("wireguard", "bird"):
        status = _clean_command_status(value.get(key))
        if status:
            cleaned[key] = status
    return cleaned


def _clean_command_status(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output = value.get("output")
    if not isinstance(output, str):
        output = ""
    if len(output) > MAX_STATUS_OUTPUT:
        output = output[:MAX_STATUS_OUTPUT] + "\n[truncated]"
    return {"ok": bool(value.get("ok", False)), "output": output}


def _load_system_status(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    return _clean_system_status(data)


def _system_summary(system: dict[str, Any]) -> str:
    parts: list[str] = []
    hostname = system.get("hostname")
    if isinstance(hostname, str) and hostname:
        parts.append(hostname)
    os_name = system.get("os")
    arch = system.get("arch")
    if isinstance(os_name, str) and isinstance(arch, str) and os_name and arch:
        parts.append(f"{os_name}/{arch}")
    uptime = system.get("uptime_seconds")
    if isinstance(uptime, int) and uptime > 0:
        parts.append(f"up {_format_uptime(uptime)}")
    load = [system.get(key) for key in ("load_1", "load_5", "load_15")]
    if all(isinstance(item, (int, float)) for item in load):
        parts.append("load " + " ".join(f"{float(item):.2f}" for item in load))
    for key, label in (("wireguard", "wg"), ("bird", "bird")):
        status = system.get(key)
        if isinstance(status, dict):
            parts.append(f"{label} {'ok' if status.get('ok') else 'fail'}")
    return " | ".join(parts) if parts else "No system heartbeat yet"


def _resource_metrics(system: dict[str, Any]) -> list[dict[str, str]]:
    metrics: list[dict[str, str]] = []
    cpu = system.get("cpu_percent")
    if isinstance(cpu, (int, float)):
        metrics.append({"label": "CPU", "value": f"{float(cpu):.1f}%"})
    memory = system.get("memory_percent")
    if isinstance(memory, (int, float)):
        value = f"{float(memory):.1f}%"
        used = system.get("memory_used_bytes")
        total = system.get("memory_total_bytes")
        if isinstance(used, int) and isinstance(total, int) and total > 0:
            value += f" {_format_bytes(used)}/{_format_bytes(total)}"
        metrics.append({"label": "Mem", "value": value})
    rx = system.get("network_rx_bytes_per_second")
    tx = system.get("network_tx_bytes_per_second")
    if isinstance(rx, (int, float)) or isinstance(tx, (int, float)):
        rx_text = _format_rate(float(rx)) if isinstance(rx, (int, float)) else "-"
        tx_text = _format_rate(float(tx)) if isinstance(tx, (int, float)) else "-"
        metrics.append({"label": "Net", "value": f"rx {rx_text} / tx {tx_text}"})
    return metrics


def _format_uptime(seconds: int) -> str:
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _format_bytes(value: int | float) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            if unit == "B":
                return f"{size:.0f}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024
    return f"{size:.1f}TiB"


def _format_rate(value: float) -> str:
    return f"{_format_bytes(value)}/s"
