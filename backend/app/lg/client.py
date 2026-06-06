from typing import Any

import httpx

from app.db.models import Agent
from app.lg.validation import validate_query_type, validate_target


class AgentClient:
    def __init__(self, timeout: float = 12.0) -> None:
        self.timeout = timeout

    async def query(self, agent: Agent, query_type: str, target: str = "") -> dict[str, Any]:
        if not agent.enabled:
            raise ValueError("Agent is disabled")
        query_type = validate_query_type(query_type)
        target = validate_target(query_type, target)
        headers = {"Authorization": f"Bearer {agent.token}"} if agent.token else {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if query_type == "status":
                response = await client.get(f"{agent.url.rstrip('/')}/v1/status", headers=headers)
            else:
                response = await client.post(
                    f"{agent.url.rstrip('/')}/v1/lg/{query_type}",
                    headers=headers,
                    json={"target": target},
                )
        response.raise_for_status()
        return response.json()

    async def peer_status(self, agent: Agent, protocol_name: str) -> dict[str, Any]:
        """Fetch one peer's detailed BIRD protocol state (`birdc show protocols all`)."""
        if not agent.enabled:
            raise ValueError("Agent is disabled")
        headers = {"Authorization": f"Bearer {agent.token}"} if agent.token else {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                f"{agent.url.rstrip('/')}/v1/peers/status",
                headers=headers,
                json={"protocol_name": protocol_name},
            )
        response.raise_for_status()
        return response.json()
