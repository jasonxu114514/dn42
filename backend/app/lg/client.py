from typing import Any

from app.agent_ws import request_agent
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
        if query_type == "status":
            return await request_agent(agent, "status", {}, self.timeout)
        return await request_agent(agent, f"lg.{query_type}", {"target": target}, self.timeout)

    async def peer_status(self, agent: Agent, protocol_name: str) -> dict[str, Any]:
        """Fetch one peer's detailed BIRD and WireGuard state."""
        if not agent.enabled:
            raise ValueError("Agent is disabled")
        return await request_agent(
            agent,
            "peers.status",
            {"protocol_name": protocol_name},
            self.timeout,
        )
