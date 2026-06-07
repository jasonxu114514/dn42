"""FindNOC integration: map a Telegram UID to the dn42 ASN(s) it controls.

FindNOC (https://findnoc.ox5.cc) is a third-party directory. We use it as a lighter alternative to
the Kioubit Mini App for the bot's /login: given the sender's *verified* Telegram UID we ask FindNOC
which ASN it controls (``/queryUser``) or confirm a specific one (``/verify``), then bind. This is a
weaker trust source than Kioubit's signed proof, so the backend treats it as advisory and always
re-checks the live API — it never trusts a UID→ASN claim supplied by the bot.

FindNOC authenticates with an API token passed as the **query parameter** ``token``; because the
token therefore lives in the request URL, this module is careful never to let a URL (or an httpx
exception message, which can embed the URL) reach logs or raised errors.

FindNOC:以 Telegram UID 反查其掌控的 dn42 ASN,作為 bot /login 比 Kioubit 更輕量的替代。其信任度
較弱,故後端僅視為輔助並每次即時查詢。token 以 query 參數傳遞,故本模組絕不讓含 token 的 URL
(或可能內含 URL 的 httpx 例外訊息)進入日誌或錯誤訊息。
"""

import logging

import httpx

from app.config import Settings
from app.peer.validation import normalize_asn_number

logger = logging.getLogger(__name__)

_TIMEOUT = 10.0


class FindNocError(ValueError):
    """A FindNOC request failed: misconfig, a rejected token, or an upstream/transport error."""


async def _get(path: str, params: dict[str, str], settings: Settings) -> httpx.Response:
    """GET ``{findnoc_api_url}/{path}`` with ``params``; map transport failures to FindNocError.

    Login is infrequent, so a per-call client is used (mirroring ``app/peer/deploy.py``). httpx
    error text can embed the full request URL — which carries ``?token=...`` — so on failure we log
    only the exception *type* and the path, never its message or the URL.
    """
    base = settings.findnoc_api_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            return await client.get(f"{base}/{path}", params=params)
    except httpx.HTTPError as exc:
        logger.warning("FindNOC %s request failed: %s", path, type(exc).__name__)
        raise FindNocError("FindNOC is unreachable") from exc


async def query_user_asns(uid: str, settings: Settings) -> list[str]:
    """Return the bare-number ASNs FindNOC lists for ``uid`` (``[]`` when the UID is unknown).

    403 means our token is bad (raises); any value that isn't a valid ASN is skipped. ASNs are
    normalised to the bare numeric form used everywhere else (see ``User.primary_asn``).
    """
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
            continue  # skip entries FindNOC returns that aren't valid ASNs
    return asns


async def verify_control(uid: str, asn_number: str, settings: Settings) -> bool:
    """Ask FindNOC whether ``uid`` controls ``AS<asn_number>``. 403 (bad token) raises."""
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
