from ipaddress import IPv6Address, ip_address, ip_interface


def asn_link_local_address(asn: str) -> str:
    suffix = normalize_dn42_asn_suffix(asn)
    address = f"fe80::{suffix}"
    try:
        ip_address(address)
    except ValueError as exc:
        raise ValueError("ASN cannot be converted into a link-local address") from exc
    return address


def normalize_link_local_address(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Peer address is required")
    try:
        interface = ip_interface(value)
    except ValueError as exc:
        raise ValueError("Peer address must be an IPv6 link-local address") from exc
    if not isinstance(interface.ip, IPv6Address) or not interface.ip.is_link_local:
        raise ValueError("Peer address must be an IPv6 link-local address")
    return str(interface.ip)


def wireguard_listen_port(asn: str) -> int:
    value = normalize_asn_number(asn)
    port = int(value[-5:])
    if port < 1 or port > 65535:
        raise ValueError("Derived WireGuard listen port is out of range")
    return port


def normalize_asn_number(asn: str) -> str:
    value = asn.strip().upper()
    if value.startswith("AS"):
        value = value[2:]
    if not value.isdigit():
        raise ValueError("ASN must be numeric")
    return value


def normalize_dn42_asn_suffix(asn: str) -> str:
    value = normalize_asn_number(asn)
    if len(value) < 4:
        suffix = value
    elif value.startswith("424242"):
        suffix = value[6:]
    else:
        suffix = value[-4:]
    suffix = suffix.lstrip("0") or "0"
    if not all(ch in "0123456789abcdefABCDEF" for ch in suffix):
        raise ValueError("ASN suffix must be valid hexadecimal for link-local generation")
    return suffix.lower()
