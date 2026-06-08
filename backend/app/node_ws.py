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

from app.db.models import Node, utcnow
from app.db.session import SessionLocal
from app.peer.validation import normalize_wireguard_key

logger = logging.getLogger("dn42.autopeer")
router = APIRouter()
MAX_STATUS_OUTPUT = 65536


class NodeOfflineError(RuntimeError):
    pass


class NodeRequestError(RuntimeError):
    pass


@dataclass(frozen=True)
class NodeAuth:
    id: str
    name: str


@dataclass
class NodeRuntime:
    online: bool = False
    connected_at: datetime | None = None
    last_seen_at: datetime | None = None
    system: dict[str, Any] = field(default_factory=dict)


class NodeConnection:
    def __init__(self, websocket: WebSocket, node: NodeAuth) -> None:
        self.websocket = websocket
        self.node = node
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


class NodeHub:
    def __init__(self) -> None:
        self._connections: dict[str, NodeConnection] = {}
        self._runtime: dict[str, NodeRuntime] = {}
        self._lock = RLock()

    async def register(self, websocket: WebSocket, node: NodeAuth) -> NodeConnection:
        connection = NodeConnection(websocket, node)
        previous: NodeConnection | None = None
        now = utcnow()
        with self._lock:
            previous = self._connections.get(node.id)
            self._connections[node.id] = connection
            state = self._runtime.setdefault(node.id, NodeRuntime())
            state.online = True
            state.connected_at = now
            state.last_seen_at = now
        if previous is not None:
            previous.fail_pending(NodeOfflineError(f"Node '{node.name}' reconnected"))
            await previous.close(code=4000, reason="replaced by a newer connection")
        _store_node_status(node.id, system=None, public_key=None)
        logger.info("Node %s connected over websocket", node.name)
        return connection

    async def unregister(self, connection: NodeConnection) -> None:
        with self._lock:
            current = self._connections.get(connection.node.id)
            if current is not connection:
                return
            self._connections.pop(connection.node.id, None)
            state = self._runtime.setdefault(connection.node.id, NodeRuntime())
            state.online = False
        connection.fail_pending(NodeOfflineError(f"Node '{connection.node.name}' disconnected"))
        logger.info("Node %s disconnected from websocket", connection.node.name)

    async def request(
        self,
        node: Node,
        command: str,
        payload: dict[str, Any] | None,
        timeout: float,
    ) -> dict[str, Any]:
        if not node.enabled:
            raise ValueError("Node is disabled")
        with self._lock:
            connection = self._connections.get(node.id)
        if connection is None:
            raise NodeOfflineError(f"Node '{node.name}' is offline")

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
            raise NodeRequestError(f"Node '{node.name}' timed out running {command}") from exc
        except NodeOfflineError:
            raise
        except Exception as exc:
            raise NodeOfflineError(f"Node '{node.name}' connection failed: {exc}") from exc
        finally:
            connection.pending.pop(request_id, None)

        error = response.get("error")
        if error:
            raise NodeRequestError(str(error))
        result = response.get("result")
        if not isinstance(result, dict):
            raise NodeRequestError("Node returned an invalid response")
        self._mark_online(connection)
        return result

    async def handle_message(self, connection: NodeConnection, message: dict[str, Any]) -> None:
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
        logger.debug("Ignoring websocket message from node %s: %r", connection.node.name, message)

    def _mark_online(
        self,
        connection: NodeConnection,
        system: dict[str, Any] | None = None,
    ) -> bool:
        """Refresh in-memory liveness for a still-current connection, returning False once it has
        been replaced. No DB I/O: this runs on the command hot path, so persistence is left to the
        periodic heartbeat (see record_seen)."""
        now = utcnow()
        with self._lock:
            if self._connections.get(connection.node.id) is not connection:
                return False
            state = self._runtime.setdefault(connection.node.id, NodeRuntime())
            state.online = True
            state.last_seen_at = now
            if system:
                state.system = system
        return True

    async def record_seen(
        self,
        connection: NodeConnection,
        *,
        system: dict[str, Any] | None,
        public_key: str | None,
    ) -> None:
        if self._mark_online(connection, system):
            _store_node_status(connection.node.id, system=system, public_key=public_key)

    def snapshot(self) -> dict[str, NodeRuntime]:
        with self._lock:
            return {
                node_id: NodeRuntime(
                    online=state.online,
                    connected_at=state.connected_at,
                    last_seen_at=state.last_seen_at,
                    system=dict(state.system),
                )
                for node_id, state in self._runtime.items()
            }


node_hub = NodeHub()


async def request_node(
    node: Node,
    command: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    return await node_hub.request(node, command, payload, timeout)


def request_node_sync(
    node: Node,
    command: str,
    payload: dict[str, Any] | None = None,
    timeout: float = 12.0,
) -> dict[str, Any]:
    try:
        return anyio.from_thread.run(request_node, node, command, payload, timeout)
    except RuntimeError as exc:
        message = str(exc)
        if "AnyIO worker thread" not in message and "can only be run from" not in message:
            raise
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(request_node(node, command, payload, timeout))
        raise


@router.websocket("/api/agents/ws")
async def node_websocket(websocket: WebSocket) -> None:
    # The dial path stays /api/agents/ws for backward compatibility with deployed agents'
    # config.json (the agent software is unchanged in how it connects). 路徑維持 /api/agents/ws
    # 以相容既有 agent 設定。
    node = _authenticate_node(websocket)
    if node is None:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    connection = await node_hub.register(websocket, node)
    try:
        while True:
            message = await websocket.receive_json()
            if isinstance(message, dict):
                await node_hub.handle_message(connection, message)
            else:
                logger.debug("Ignoring non-object websocket message from node %s", node.name)
    except WebSocketDisconnect:
        pass
    except ValueError as exc:
        logger.warning("Invalid websocket JSON from node %s: %s", node.name, exc)
    finally:
        await node_hub.unregister(connection)


def node_runtime_context(nodes: list[Node]) -> dict[str, dict[str, Any]]:
    live = node_hub.snapshot()
    context: dict[str, dict[str, Any]] = {}
    for node in nodes:
        state = live.get(node.id)
        stored_system = _load_system_status(node.system_status_json)
        system = state.system if state and state.system else stored_system
        last_seen_at = state.last_seen_at if state and state.last_seen_at else node.last_seen_at
        context[node.id] = {
            "online": bool(state and state.online),
            "connected_at": state.connected_at if state else None,
            "last_seen_at": last_seen_at,
            "system": system,
            "system_summary": _system_summary(system),
            "resource_metrics": _resource_metrics(system),
        }
    return context


def _authenticate_node(websocket: WebSocket) -> NodeAuth | None:
    name = websocket.query_params.get("name", "").strip()
    if not name:
        return None
    token = _bearer_token(websocket.headers.get("authorization", ""))
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.name == name).one_or_none()
        if node is None or not node.enabled:
            return None
        if node.token and not secrets.compare_digest(token, node.token):
            return None
        if not node.token and token:
            return None
        return NodeAuth(id=node.id, name=node.name)


def _bearer_token(header: str) -> str:
    prefix = "Bearer "
    if header.startswith(prefix):
        return header[len(prefix) :]
    return ""


def _store_node_status(
    node_id: str,
    *,
    system: dict[str, Any] | None,
    public_key: str | None,
) -> None:
    with SessionLocal() as db:
        node = db.query(Node).filter(Node.id == node_id).one_or_none()
        if node is None:
            return
        node.last_seen_at = utcnow()
        if system:
            node.system_status_json = json.dumps(system, sort_keys=True, separators=(",", ":"))
        if public_key:
            try:
                node.wg_public_key = normalize_wireguard_key(public_key)
            except ValueError:
                logger.warning("Node %s sent an invalid WireGuard public key", node.name)
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
