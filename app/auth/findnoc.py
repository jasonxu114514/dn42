"""FindNOC integration: map a Telegram UID to the dn42 ASN(s) it controls.

FindNOC authenticates with an API token passed as the query parameter ``token``. Because the
token lives in the request URL, this module never logs request URLs or raw urllib exception text.
"""

import asyncio
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from app.config import Settings
from app.peer.validation import normalize_asn_number

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0


class FindNocError(ValueError):
    """A FindNOC request failed: misconfig, rejected token, upstream, or transport error."""


@dataclass(frozen=True)
class FindNocResponse:
    status_code: int
    body: str

    def json(self) -> object:
        return json.loads(self.body)


def _url(path: str, params: dict[str, str], settings: Settings) -> str:
    base = settings.findnoc_api_url.strip().rstrip("/")
    if not base:
        raise FindNocError("FindNOC API URL is not configured")
    return f"{base}/{path}?{urllib.parse.urlencode(params)}"


def _get_sync(path: str, params: dict[str, str], settings: Settings) -> FindNocResponse:
    request = urllib.request.Request(
        _url(path, params, settings),
        headers={
            "Accept": "application/json",
            "User-Agent": "dn42-autopeer-findnoc/0.1",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            return FindNocResponse(response.status, body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return FindNocResponse(exc.code, body)
    except (OSError, TimeoutError, ValueError) as exc:
        logger.warning("FindNOC %s request failed: %s", path, type(exc).__name__)
        raise FindNocError("FindNOC is unreachable") from None


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
