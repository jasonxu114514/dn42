"""Verify Kioubit dn42 auth tokens: an ECDSA signature over a base64-JSON ``params`` blob.

驗證 Kioubit dn42 認證權杖：對 base64-JSON 的 ``params`` 內容做 ECDSA 簽章驗證。後端只信任此處
驗證過的資料——先核對簽章、時間戳（防重放）與 domain，再回傳解析後的 ASN／mnt 等欄位。
"""

import base64
import json
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


class KioubitAuthError(ValueError):
    pass


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [str(value)]


class KioubitVerifier:
    def __init__(self, public_key_path: str, domain: str, max_age_seconds: int = 60) -> None:
        self.domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        self.max_age_seconds = max_age_seconds
        key_path = Path(public_key_path)
        if not key_path.exists():
            self.public_key = None
            return
        self.public_key = serialization.load_pem_public_key(key_path.read_bytes())

    def verify(self, params: str, signature: str) -> dict[str, Any]:
        if self.public_key is None:
            raise KioubitAuthError("Kioubit public key is not installed")
        if not isinstance(self.public_key, ec.EllipticCurvePublicKey):
            raise KioubitAuthError("Kioubit public key is not an EC public key")

        try:
            signature_bytes = base64.b64decode(signature)
        except ValueError as exc:
            raise KioubitAuthError("Invalid signature base64") from exc

        try:
            self.public_key.verify(signature_bytes, params.encode(), ec.ECDSA(hashes.SHA512()))
        except InvalidSignature as exc:
            raise KioubitAuthError("Invalid Kioubit signature") from exc

        try:
            decoded = base64.b64decode(params)
            data = json.loads(decoded)
        except (ValueError, json.JSONDecodeError) as exc:
            raise KioubitAuthError("Invalid Kioubit params") from exc

        # Replay window: reject tokens whose timestamp is more than max_age_seconds from now
        # (in either direction, to tolerate small clock skew). Domain must match exactly so a
        # token minted for another site cannot be replayed here.
        # 重放窗口：拒絕時間戳與現在相差超過 max_age_seconds 的權杖（雙向，以容忍時鐘偏差）；
        # domain 必須完全相符，避免他站簽發的權杖被重放至此。
        now = time.time()
        auth_time = float(data.get("time", 0))
        if abs(now - auth_time) > self.max_age_seconds:
            raise KioubitAuthError("Kioubit token has expired")

        if str(data.get("domain", "")) != self.domain:
            raise KioubitAuthError("Kioubit token was issued for a different domain")

        asn = str(data.get("asn", "")).strip()
        if not asn:
            raise KioubitAuthError("Kioubit token did not include an ASN")

        data["asn"] = asn
        data["allowed4"] = _normalize_list(data.get("allowed4"))
        data["allowed6"] = _normalize_list(data.get("allowed6"))
        data["mnt"] = _normalize_list(data.get("mnt"))
        data["user_token"] = str(data.get("user_token", ""))
        return data
