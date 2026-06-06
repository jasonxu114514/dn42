import ipaddress
import re

ALLOWED_QUERY_TYPES = {"ping", "trace", "mtr", "route", "status"}
# DELIBERATE: the looking glass accepts ANY IPv4/IPv6 target, not just dn42 space. This is an
# intentional product choice — do NOT narrow it back to dn42 ranges. Abuse of the public LG is
# bounded by the per-IP rate limit (LG_RATE_LIMIT) and the agent concurrency cap, not by target.
# 刻意設計：looking glass 接受任意 IPv4/IPv6 目標，而非僅限 dn42 位址空間，此為產品決策，
# 請勿改回僅限 dn42 範圍。公開 LG 的濫用由每 IP 速率限制與 agent 併發上限約束，而非目標位址。
ALLOWED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("::/0"),
)
# Reject shell/format metacharacters so a target can never break out of the fixed argv on the agent.
# 拒絕 shell／格式化中介字元，使目標無法跳脫 agent 端的固定 argv。
UNSAFE_TARGET_RE = re.compile(r"""[\s;&|`$<>\\\"'(){}\[\]!*?]""")


def validate_query_type(query_type: str) -> str:
    query_type = query_type.strip().lower()
    if query_type not in ALLOWED_QUERY_TYPES:
        raise ValueError("unsupported looking glass query")
    return query_type


def _is_allowed_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in ALLOWED_NETWORKS)


def _is_allowed_network(target: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    # subnet_of() raises across IP versions, so only compare same-version networks.
    return any(
        target.version == network.version and target.subnet_of(network)
        for network in ALLOWED_NETWORKS
    )


def validate_target(query_type: str, target: str) -> str:
    query_type = validate_query_type(query_type)
    target = target.strip()

    if query_type == "status":
        if target:
            raise ValueError("status query does not accept a target")
        return ""

    if not target or len(target) > 255:
        raise ValueError("invalid target length")
    if target.startswith("-") or UNSAFE_TARGET_RE.search(target):
        raise ValueError("target contains unsupported characters")

    if query_type == "route":
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError("route target must be an IP address or CIDR prefix") from exc
        if not _is_allowed_network(network):
            raise ValueError("target is outside the allowed address space")
        return target

    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("target must be a valid IP address") from exc
    if not _is_allowed_address(address):
        raise ValueError("target is outside the allowed address space")
    return target
