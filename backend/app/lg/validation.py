import ipaddress
import re

ALLOWED_QUERY_TYPES = {"ping", "trace", "mtr", "route"}
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
# A DNS hostname accepted for ping/trace/mtr (e.g. "wiki.dn42", "example.com"): RFC-1123 labels of
# letters/digits/hyphen, each 1–63 chars and not starting or ending with a hyphen, joined by dots,
# with at least one dot, total length ≤ 253. ping/traceroute resolve the name themselves on the
# agent; since the LG already allows any resolved address, accepting a hostname does not widen the
# reachable target space. route stays IP/prefix only — BIRD does not resolve names.
# ping/trace/mtr 接受的 DNS 主機名（如 "wiki.dn42"）：RFC-1123 標籤,
# 由字母／數字／連字號組成,每段 1–63 字元且不以連字號開頭或結尾,以點相連,
# 至少含一個點,總長 ≤ 253。ping/traceroute 於 agent 端自行解析；
# 因 LG 本就允許任意解析後位址,接受主機名不會擴大可達目標範圍。
# route 仍僅限 IP／前綴——BIRD 不解析名稱。
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


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
        # Not an IP — accept a valid hostname (ping/traceroute resolve it on the agent).
        if HOSTNAME_RE.match(target):
            return target
        raise ValueError("target must be a valid IP address or hostname") from exc
    if not _is_allowed_address(address):
        raise ValueError("target is outside the allowed address space")
    return target
