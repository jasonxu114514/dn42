from typing import Any

from app.agent_ws import request_agent
from app.db.models import Agent
from app.lg.summary import summarize_peer_bird, summarize_protocols, summarize_wireguard
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
            # Replace the raw ``birdc show protocols`` table with a per-session summary; the
            # diagnostic queries (ping/trace/mtr/route) are returned verbatim.
            result = await request_agent(agent, "status", {}, self.timeout)
            output = result.get("output")
            if isinstance(output, str):
                result["output"] = summarize_protocols(output)
            return result
        return await request_agent(agent, f"lg.{query_type}", {"target": target}, self.timeout)

    async def peer_status(self, agent: Agent, protocol_name: str) -> dict[str, Any]:
        """Fetch one peer's BIRD and WireGuard state, condensed to key info (state / handshake)."""
        if not agent.enabled:
            raise ValueError("Agent is disabled")
        result = await request_agent(
            agent,
            "peers.status",
            {"protocol_name": protocol_name},
            self.timeout,
        )
        output = result.get("output")
        wireguard = result.get("wireguard")
        if isinstance(output, str):
            result["output"] = summarize_peer_bird(output)
        if isinstance(wireguard, str):
            result["wireguard"] = summarize_wireguard(wireguard)
        return result
