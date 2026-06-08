"""Validation/normalisation of user-supplied peer fields, plus dn42 ASN-derived defaults.

驗證並正規化使用者輸入的對等欄位（端點、WireGuard 金鑰、link-local 位址），並從 dn42 ASN
推導預設值（WireGuard 監聽埠與 fe80:: link-local 位址）。這些值會寫入路由器的 WireGuard/BIRD
設定，因此每個輸入都需嚴格檢查。
"""

import re
from ipaddress import IPv6Address, IPv6Network, ip_address, ip_interface

_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\Z)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?"
)
_WIREGUARD_KEY_RE = re.compile(r"[A-Za-z0-9+/]{43}=")
# dn42 BGP runs in-tunnel over an IPv6 link-local (fe80::/10) or a ULA (fc00::/7, which covers
# fd00::/8). A link-local neighbor needs a %interface scope in BIRD; a ULA does not.
_ULA_NETWORK = IPv6Network("fc00::/7")
DEFAULT_WIREGUARD_MTU = 1420
MIN_WIREGUARD_MTU = 1280
MAX_WIREGUARD_MTU = 9000


def normalize_endpoint(value: str) -> str:
    """Validate a WireGuard endpoint as ``host:port``, or return ``""`` when blank.

    A blank endpoint is allowed: the peer then dials us (we are the listener), so the generated
    wg-quick config simply omits the ``Endpoint`` line. A non-blank value is validated and may not
    contain newlines, whitespace, or shell/config metacharacters so it can never inject extra
    directives (e.g. ``PostUp``) into the config. 端點留空代表由對端撥號連我方,設定檔即省略
    ``Endpoint`` 行;非空值則嚴格驗證。
    """
    value = value.strip()
    if not value:
        return ""
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


def extract_node_host(value: str) -> str:
    """Reduce a stored Node public address to a bare host (drop scheme, path, brackets, and :port).

    Tolerant by design so a legacy URL-form value (``https://pop.example.net``) and the new
    bare-host form both resolve to the host a peer's WireGuard should dial. A bare IPv6 literal is
    returned unbracketed (it always has ≥2 colons, so it is not mistaken for ``host:port``).
    """
    host = value.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.startswith("[") and "]" in host:  # [ipv6] or [ipv6]:port
        return host[1:].split("]", 1)[0]
    if host.count(":") == 1:  # host:port — a bare IPv6 always has ≥2 colons
        host = host.split(":", 1)[0]
    return host


def normalize_node_host(value: str) -> str:
    """Validate a Node's public address: a bare IPv4, IPv6, or domain — no scheme, no port.

    Only the host is stored; the WireGuard port a peer dials is derived from its ASN
    (see ``wireguard_listen_port``). A pasted scheme/port is stripped for convenience, and the
    remainder must be a valid address. 本節點對外位址：純 IPv4 / IPv6 / 網域（不含 scheme 與埠）。
    """
    raw = value.strip()
    if not raw:
        raise ValueError("Node public address is required")
    if len(raw) > 255:
        raise ValueError("Node public address is too long")
    host = extract_node_host(raw)
    if host:
        try:
            ip_address(host)  # accepts both IPv4 and IPv6 literals
            return host
        except ValueError:
            pass
        if _HOSTNAME_RE.fullmatch(host):
            return host
    raise ValueError("Node public address must be an IPv4, IPv6, or domain (no scheme or port)")


def normalize_wireguard_key(value: str) -> str:
    """Validate a base64-encoded WireGuard public key (32 bytes -> 44 chars)."""
    value = value.strip()
    if not _WIREGUARD_KEY_RE.fullmatch(value):
        raise ValueError("WireGuard public key must be a 44-character base64 value")
    return value


def normalize_optional_ip(value: str, *, version: int) -> str:
    """Validate an optional IPv4/IPv6 address or CIDR (blank allowed); return the trimmed value.

    Used for the per-node DN42 IPv4/IPv6 fields, which are informational (shown to peers) and may
    be left empty. 用於每節點 DN42 IPv4/IPv6 欄位(可留空,僅供顯示)。"""
    value = (value or "").strip()
    if not value:
        return ""
    try:
        interface = ip_interface(value)
    except ValueError as exc:
        raise ValueError(f"Must be a valid IPv{version} address") from exc
    if interface.version != version:
        raise ValueError(f"Must be an IPv{version} address")
    return value


def normalize_wireguard_mtu(value: int | str | None = None) -> int:
    """Validate a wg-quick MTU value; blank input falls back to the default."""
    if value is None:
        return DEFAULT_WIREGUARD_MTU
    if isinstance(value, int):
        mtu = value
    else:
        value = value.strip()
        if not value:
            return DEFAULT_WIREGUARD_MTU
        if not value.isdigit():
            raise ValueError("WireGuard MTU must be an integer")
        mtu = int(value)
    if not MIN_WIREGUARD_MTU <= mtu <= MAX_WIREGUARD_MTU:
        raise ValueError(
            f"WireGuard MTU must be between {MIN_WIREGUARD_MTU} and {MAX_WIREGUARD_MTU}"
        )
    return mtu


def asn_link_local_address(asn: str) -> str:
    """Derive the peer's IPv6 link-local address from its ASN: ``fe80::<suffix>``.

    依 ASN 推導對等端的 IPv6 link-local 位址（fe80::<後綴>），與 web portal 預填的預設一致。
    """
    suffix = normalize_dn42_asn_suffix(asn)
    address = f"fe80::{suffix}"
    try:
        ip_address(address)
    except ValueError as exc:
        raise ValueError("ASN cannot be converted into a link-local address") from exc
    return address


def is_link_local(value: str) -> bool:
    """True when ``value`` (a bare IP or IP/prefix) is an IPv6 link-local (fe80::/10) address.

    BIRD needs a ``%interface`` scope on a link-local neighbor/source address but not on a ULA,
    so config generation branches on this. 判斷是否為 IPv6 link-local;link-local 的 BIRD
    neighbor/source 需加 %介面 scope,ULA 則否。"""
    try:
        ip = ip_interface(value.strip()).ip
    except ValueError:
        return False
    return isinstance(ip, IPv6Address) and ip.is_link_local


def normalize_tunnel_address(value: str) -> str:
    """Validate a peer's in-tunnel BGP address: an IPv6 link-local (fe80::/10) or ULA (fc00::/7).

    dn42 peerings run BGP over either the WireGuard link-local (the default) or a ULA; both are
    accepted. Returns the bare address, dropping any ``/prefix``. 對等隧道內的 BGP 位址:
    IPv6 link-local(預設)或 ULA,皆接受;回傳去除前綴的純位址。
    """
    value = value.strip()
    if not value:
        raise ValueError("Peer address is required")
    try:
        ip = ip_interface(value).ip
    except ValueError as exc:
        raise ValueError("Peer address must be an IPv6 link-local or ULA address") from exc
    if not isinstance(ip, IPv6Address) or not (ip.is_link_local or ip in _ULA_NETWORK):
        raise ValueError(
            "Peer address must be an IPv6 link-local (fe80::/10) or ULA (fd00::/8) address"
        )
    return str(ip)


def wireguard_listen_port(asn: str) -> int:
    """Derive the WireGuard listen port from the ASN's last 5 digits (4242420090 -> 20090).

    取 ASN 後 5 位數字作為 WireGuard 監聽埠（例如 4242420090 → 20090）；因為每個 PoP 對每個
    ASN 至多一個對等端，所以各對等端的埠不會衝突。
    """
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
    """Reduce an ASN to the short hex suffix used in fe80::<suffix> link-local addresses.

    將 ASN 縮減為 link-local 位址 fe80::<後綴> 所用的短十六進位後綴。
    """
    value = normalize_asn_number(asn)
    # dn42 ASNs are 4242420000+: drop the shared 424242 prefix (4242420099 -> "0099"),
    # otherwise keep the last 4 digits; ASNs shorter than 4 digits are used as-is.
    # dn42 ASN 多為 4242420000+：去掉共用的 424242 前綴（4242420099 → "0099"），否則取後 4 位；
    # 不足 4 位的 ASN 原樣保留。
    if len(value) < 4:
        suffix = value
    elif value.startswith("424242"):
        suffix = value[6:]
    else:
        suffix = value[-4:]
    # Strip leading zeros for a compact address (fe80::99, not fe80::0099); keep one "0".
    # 去除前導零讓位址精簡（fe80::99 而非 fe80::0099），但全零時保留一個 "0"。
    suffix = suffix.lstrip("0") or "0"
    if not all(ch in "0123456789abcdefABCDEF" for ch in suffix):
        raise ValueError("ASN suffix must be valid hexadecimal for link-local generation")
    return suffix.lower()
