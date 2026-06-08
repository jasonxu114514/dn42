from typing import Any

from app.db.models import Node
from app.lg.validation import validate_query_type, validate_target
from app.node_ws import request_node


class NodeClient:
    def __init__(self, timeout: float = 12.0) -> None:
        self.timeout = timeout

    async def query(self, node: Node, query_type: str, target: str = "") -> dict[str, Any]:
        if not node.enabled:
            raise ValueError("Node is disabled")
        query_type = validate_query_type(query_type)
        target = validate_target(query_type, target)
        return await request_node(node, f"lg.{query_type}", {"target": target}, self.timeout)

    async def peer_status(self, node: Node, protocol_name: str) -> dict[str, Any]:
        """Fetch one peer's full, unmodified BIRD and WireGuard state.

        Returned verbatim — the admin live-status page shows the complete command output. The
        portal peer-detail page and the bot's ``/listpeers`` condense it to key info at their own
        call sites via ``summarize_peer_bird`` / ``summarize_wireguard``.
        """
        if not node.enabled:
            raise ValueError("Node is disabled")
        return await request_node(
            node,
            "peers.status",
            {"protocol_name": protocol_name},
            self.timeout,
        )
