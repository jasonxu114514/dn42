from typing import Any

import httpx

from app.db.models import Agent
from app.lg.validation import validate_query_type, validate_target

# Process-wide pooled HTTP client. Repeated looking-glass queries — and especially the per-peer
# fan-out behind the Telegram /status command — reuse connections instead of paying a fresh
# TCP/TLS handshake each time. Created lazily on first use (so it binds to the running event loop)
# and closed via aclose_shared_client() from the FastAPI lifespan shutdown.
_shared_client: httpx.AsyncClient | None = None


def _client() -> httpx.AsyncClient:
    global _shared_client
    if _shared_client is None:
        _shared_client = httpx.AsyncClient()
    return _shared_client


async def aclose_shared_client() -> None:
    """Close the pooled client. Safe to call even if it was never created."""
    global _shared_client
    if _shared_client is not None:
        await _shared_client.aclose()
        _shared_client = None


class AgentClient:
    def __init__(self, timeout: float = 12.0) -> None:
        self.timeout = timeout

    async def query(self, agent: Agent, query_type: str, target: str = "") -> dict[str, Any]:
        if not agent.enabled:
            raise ValueError("Agent is disabled")
        query_type = validate_query_type(query_type)
        target = validate_target(query_type, target)
        headers = {"Authorization": f"Bearer {agent.token}"} if agent.token else {}
        base = agent.url.rstrip("/")
        client = _client()
        if query_type == "status":
            response = await client.get(f"{base}/v1/status", headers=headers, timeout=self.timeout)
        else:
            response = await client.post(
                f"{base}/v1/lg/{query_type}",
                headers=headers,
                json={"target": target},
                timeout=self.timeout,
            )
        response.raise_for_status()
        return response.json()

    async def peer_status(self, agent: Agent, protocol_name: str) -> dict[str, Any]:
        """Fetch one peer's detailed BIRD protocol state (`birdc show protocols all`)."""
        if not agent.enabled:
            raise ValueError("Agent is disabled")
        headers = {"Authorization": f"Bearer {agent.token}"} if agent.token else {}
        response = await _client().post(
            f"{agent.url.rstrip('/')}/v1/peers/status",
            headers=headers,
            json={"protocol_name": protocol_name},
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()
