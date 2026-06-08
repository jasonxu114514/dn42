"""Condense verbose ``birdc``/``wg`` status output into one or two lines of key info.

These run server-side so the web looking glass and the Telegram bot show the same concise
summaries — is the BGP session up? if not, why? is the WireGuard tunnel handshaking? — instead of
the full raw command dumps. If the output does not match the expected shape (an error string, an
empty body, an unfamiliar format), the original text is returned capped to a few lines so the
reason something is down is never hidden.

將冗長的 birdc／wg 狀態輸出濃縮為一兩行關鍵資訊(BGP 是否建立?否則原因為何?WireGuard 是否有
握手?),於伺服器端執行,使網頁 looking glass 與 Telegram bot 顯示一致的精簡摘要。當輸出不符
預期格式時(錯誤訊息、空白、未知格式),回傳裁切後的原文,避免隱藏異常原因。
"""

import re

# A channel's "Routes: X imported, Y filtered, Z exported, W preferred" line.
_ROUTES_RE = re.compile(r"(\d+)\s+imported.*?(\d+)\s+exported")


def _capped(text: str, *, max_lines: int = 6, max_chars: int = 400) -> str:
    """The trimmed text capped to a few lines/chars — the fallback when parsing fails."""
    text = (text or "").strip()
    if not text:
        return "(no output)"
    lines = text.splitlines()
    clipped = "\n".join(lines[:max_lines])
    if len(lines) > max_lines or len(clipped) > max_chars:
        clipped = clipped[:max_chars].rstrip() + " …"
    return clipped


def summarize_peer_bird(output: str) -> str:
    """Summarize ``birdc show protocols all <name>`` for one peer: state + routes, or the reason.

    Established → ``Established · routes <imp> in / <exp> out`` (summed across channels); otherwise
    ``<state> — <Last error>`` so a down session shows why.
    """
    text = output or ""
    state_match = re.search(r"BGP state:\s*(\S+)", text)
    if not state_match:
        return _capped(text)
    state = state_match.group(1)
    if state.lower() == "established":
        pairs = _ROUTES_RE.findall(text)
        if pairs:
            imported = sum(int(imp) for imp, _ in pairs)
            exported = sum(int(exp) for _, exp in pairs)
            return f"Established · routes {imported} in / {exported} out"
        return "Established"
    error = re.search(r"Last error:\s*(.+)", text)
    reason = error.group(1).strip() if error else ""
    return f"{state} — {reason}" if reason else state


def summarize_wireguard(output: str) -> str:
    """Summarize ``wg show <iface>`` for one tunnel: up/stale/down + handshake age and transfer."""
    text = (output or "").strip()
    if not text or "No such device" in text or "Unable to access interface" in text:
        return "interface down"
    if "interface:" not in text and "peer:" not in text:
        return _capped(text)
    endpoint = re.search(r"endpoint:\s*(\S+)", text)
    handshake = re.search(r"latest handshake:\s*(.+)", text)
    transfer = re.search(r"transfer:\s*(.+)", text)
    # No "latest handshake" line (or "(none)") → the tunnel has never completed a handshake.
    age = handshake.group(1).strip() if handshake else ""
    if not age or age.lower() == "(none)":
        suffix = f" · endpoint {endpoint.group(1)}" if endpoint else ""
        return f"no handshake yet{suffix}"
    # A handshake measured in hours/days means keepalive has lapsed — flag it as stale.
    state = "stale" if re.search(r"\b(hour|day)", age) else "up"
    parts = [f"{state} · handshake {age}"]
    if transfer:
        xfer = transfer.group(1).strip()
        amounts = re.match(r"(.+?)\s+received,\s*(.+?)\s+sent", xfer)
        parts.append(f"{amounts.group(1)} rx / {amounts.group(2)} sent" if amounts else xfer)
    return " · ".join(parts)
