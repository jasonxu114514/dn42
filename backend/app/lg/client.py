from typing import Any

import httpx

from app.db.models import Node


ALLOWED_QUERY_TYPES = {"ping", "mtr", "route", "status"}


class AgentClient:
    def __init__(self, timeout: float = 12.0) -> None:
        self.timeout = timeout

    async def query(self, node: Node, query_type: str, target: str = "") -> dict[str, Any]:
        if query_type not in ALLOWED_QUERY_TYPES:
            raise ValueError("Unsupported looking glass query")
        headers = {"Authorization": f"Bearer {node.agent_token}"} if node.agent_token else {}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if query_type == "status":
                response = await client.get(f"{node.agent_url.rstrip('/')}/v1/status", headers=headers)
            else:
                response = await client.post(
                    f"{node.agent_url.rstrip('/')}/v1/lg/{query_type}",
                    headers=headers,
                    json={"target": target},
                )
        response.raise_for_status()
        return response.json()
