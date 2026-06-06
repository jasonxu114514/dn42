import ipaddress
import re


ALLOWED_QUERY_TYPES = {"ping", "mtr", "route", "status"}
DN42_NETWORKS = (
    ipaddress.ip_network("172.20.0.0/14"),
    ipaddress.ip_network("fd00::/8"),
)
UNSAFE_TARGET_RE = re.compile(r"""[\s;&|`$<>\\\"'(){}\[\]!*?]""")


def validate_query_type(query_type: str) -> str:
    query_type = query_type.strip().lower()
    if query_type not in ALLOWED_QUERY_TYPES:
        raise ValueError("unsupported looking glass query")
    return query_type


def _is_dn42_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in DN42_NETWORKS)


def _is_dn42_network(target: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return any(target.subnet_of(network) for network in DN42_NETWORKS)


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
            raise ValueError("route target must be a DN42 IP address or CIDR prefix") from exc
        if not _is_dn42_network(network):
            raise ValueError("target must be inside DN42 address space")
        return target

    try:
        address = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("target must be a DN42 IP address") from exc
    if not _is_dn42_address(address):
        raise ValueError("target must be inside DN42 address space")
    return target
