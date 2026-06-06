from typing import Any

import httpx

from app.db.models import Node
from app.lg.validation import validate_query_type, validate_target


class AgentClient:
    def __init__(self, timeout: float = 12.0) -> None:
        self.timeout = timeout

    async def query(self, node: Node, query_type: str, target: str = "") -> dict[str, Any]:
        query_type = validate_query_type(query_type)
        target = validate_target(query_type, target)
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
