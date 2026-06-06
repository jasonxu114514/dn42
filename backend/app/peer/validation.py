import re
from ipaddress import IPv6Address, ip_address, ip_interface

_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?"
)
_WIREGUARD_KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=")


def normalize_endpoint(value: str) -> str:
    """Validate a WireGuard endpoint as ``host:port``.

    Rejects newlines, whitespace, and shell/config metacharacters so the value can never
    inject extra directives (e.g. ``PostUp``) into the generated wg-quick config.
    """
    value = value.strip()
    if not value:
        raise ValueError("Endpoint is required")
    if len(value) > 255:
        raise ValueError("Endpoint is too long")
    for ch in value:
        if ord(ch) < 33 or ord(ch) > 126:
            raise ValueError("Endpoint must not contain spaces or control characters")

    host, sep, port = value.rpartition(":")
    if not sep or not host or not port:
        raise ValueError("Endpoint must be in host:port form")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("Endpoint port must be between 1 and 65535")

    if host.startswith("[") and host.endswith("]"):
        try:
            IPv6Address(host[1:-1])
        except ValueError as exc:
            raise ValueError("Endpoint IPv6 address is invalid") from exc
        return f"{host}:{port}"
    if ":" in host:
        raise ValueError("IPv6 endpoints must be written as [address]:port")
    try:
        ip_address(host)
        return f"{host}:{port}"
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(host):
        raise ValueError("Endpoint host must be an IP address or hostname")
    return f"{host}:{port}"


def normalize_wireguard_key(value: str) -> str:
    """Validate a base64-encoded WireGuard public key (32 bytes -> 44 chars)."""
    value = value.strip()
    if not _WIREGUARD_KEY_RE.fullmatch(value):
        raise ValueError("WireGuard public key must be a 44-character base64 value")
    return value


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
