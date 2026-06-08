"""FindNOC integration: map a Telegram UID to the dn42 ASN(s) it controls."""

import asyncio
import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from app.config import Settings
from app.peer.validation import normalize_asn_number

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0


class FindNocError(ValueError):
    """A FindNOC request failed: misconfig, rejected token, upstream, or transport error."""


class FindNocResponse:
    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body

    def json(self) -> object:
        return json.loads(self.body)


def _get_sync(path: str, params: dict[str, str], settings: Settings) -> FindNocResponse:
    base = settings.findnoc_api_url.rstrip("/")
    query = urllib.parse.urlencode(params)
    request = urllib.request.Request(f"{base}/{path}?{query}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            return FindNocResponse(response.status, body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return FindNocResponse(exc.code, body)
    except (OSError, TimeoutError) as exc:
        logger.warning("FindNOC %s request failed: %s", path, type(exc).__name__)
        raise FindNocError("FindNOC is unreachable") from exc


async def _get(path: str, params: dict[str, str], settings: Settings) -> FindNocResponse:
    return await asyncio.to_thread(_get_sync, path, params, settings)


async def query_user_asns(uid: str, settings: Settings) -> list[str]:
    """Return the bare-number ASNs FindNOC lists for ``uid``."""
    response = await _get(
        "queryUser", {"userid": uid, "token": settings.findnoc_api_token}, settings
    )
    if response.status_code == 404:
        return []
    if response.status_code == 403:
        logger.warning("FindNOC rejected our API token on /queryUser")
        raise FindNocError("FindNOC rejected our API token")
    if response.status_code != 200:
        raise FindNocError(f"FindNOC /queryUser returned HTTP {response.status_code}")
    try:
        items = response.json()
    except ValueError as exc:
        raise FindNocError("FindNOC returned a non-JSON response") from exc
    if not isinstance(items, list):
        raise FindNocError("FindNOC returned an unexpected payload")
    asns: list[str] = []
    for item in items:
        try:
            asns.append(normalize_asn_number(str(item)))
        except ValueError:
            continue
    return asns


async def verify_control(uid: str, asn_number: str, settings: Settings) -> bool:
    """Ask FindNOC whether ``uid`` controls ``AS<asn_number>``."""
    response = await _get(
        "verify",
        {"userid": uid, "ASN": f"AS{asn_number}", "token": settings.findnoc_api_token},
        settings,
    )
    if response.status_code == 403:
        logger.warning("FindNOC rejected our API token on /verify")
        raise FindNocError("FindNOC rejected our API token")
    if response.status_code != 200:
        raise FindNocError(f"FindNOC /verify returned HTTP {response.status_code}")
    try:
        body = response.json()
    except ValueError as exc:
        raise FindNocError("FindNOC returned a non-JSON response") from exc
    return bool(body.get("result")) if isinstance(body, dict) else False
