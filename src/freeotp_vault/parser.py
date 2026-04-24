"""
Parser for FreeOTP (original) and FreeOTP+ JSON export files.

Normalises every token to the internal dict format:
{
    "issuer":  str,
    "label":   str,
    "secret":  str,   # base32-encoded, always uppercase, no padding stripped
    "type":    "TOTP" | "HOTP",
    "algo":    "SHA1" | "SHA256" | "SHA512",
    "digits":  int,
    "period":  int,   # TOTP only, default 30
    "counter": int,   # HOTP only, default 0
}
"""

from __future__ import annotations

import base64
import json
import re
from typing import TypedDict


class Token(TypedDict):
    issuer: str
    label: str
    secret: str
    type: str
    algo: str
    digits: int
    period: int
    counter: int


def _bytes_to_base32(raw: bytes) -> str:
    """Encode raw bytes to uppercase base32 without padding."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _normalise_secret(secret: object) -> str:
    """Convert secret from any FreeOTP representation to a bare base32 string.

    FreeOTP (original): signed int8 JSON array, e.g. [-10, 20, ...]
    FreeOTP+:           base32 string OR int8 array (same app, newer versions)
    """
    if isinstance(secret, list):
        raw = bytes(b & 0xFF for b in secret)
        return _bytes_to_base32(raw)
    if isinstance(secret, str):
        cleaned = secret.strip().upper().rstrip("=")
        if not re.fullmatch(r"[A-Z2-7]+", cleaned):
            raise ValueError(f"Secret does not look like base32: {secret!r}")
        return cleaned
    raise ValueError(f"Unrecognised secret type: {type(secret)}")


def parse_freeotp_json(raw: str) -> list[Token]:
    """Parse a FreeOTP or FreeOTP+ JSON export string.

    Args:
        raw: UTF-8 string content of the exported JSON file.

    Returns:
        List of normalised token dicts.

    Raises:
        ValueError: On malformed JSON or missing required fields.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc

    if isinstance(obj, list):
        raw_tokens = obj
    elif isinstance(obj, dict):
        raw_tokens = obj.get("tokens", [])
        if not isinstance(raw_tokens, list):
            raise ValueError("'tokens' field is not a list.")
    else:
        raise ValueError("Unexpected JSON root type.")

    tokens: list[Token] = []
    for i, t in enumerate(raw_tokens):
        if not isinstance(t, dict):
            raise ValueError(f"Token #{i} is not an object.")

        try:
            secret = _normalise_secret(t["secret"])
        except KeyError:
            raise ValueError(f"Token #{i} missing 'secret' field.")

        token_type = str(t.get("type", "TOTP")).upper()
        if token_type not in ("TOTP", "HOTP"):
            token_type = "TOTP"

        algo = str(t.get("algo") or t.get("algorithm") or "SHA1").upper()
        if algo not in ("SHA1", "SHA256", "SHA512"):
            algo = str(t.get("algorithm") or "SHA1").upper()
            if algo not in ("SHA1", "SHA256", "SHA512"):
                algo = "SHA1"

        tokens.append(
            {
                "issuer": str(t.get("issuerExt", t.get("issuer", ""))),
                "label": str(t.get("label", t.get("accountName", ""))),
                "secret": secret,
                "type": token_type,
                "algo": algo,
                "digits": int(t.get("digits", 6)),
                "period": int(t.get("period", 30)),
                "counter": int(t.get("counter", 0)),
            }
        )

    if not tokens:
        raise ValueError("No tokens found in the exported file.")

    return tokens


class GdriveAuthData(TypedDict):
    client_id: str
    client_secret: str
    refresh_token: str


def extract_gdrive_auth(raw: str) -> GdriveAuthData | None:
    """Extract Google Drive OAuth credentials from a FreeOTP JSON export.

    Looks for gdrive/auth fields in the root dict or any token entry.
    Returns None if no auth data is present.
    """
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None

    if isinstance(obj, dict):
        auth = obj.get("gdrive", obj.get("auth", {}))
        if not isinstance(auth, dict):
            return None
        client_id = auth.get("client_id", "")
        client_secret = auth.get("client_secret", "")
        refresh_token = auth.get("refresh_token", "")
        if client_id or client_secret or refresh_token:
            return GdriveAuthData(
                client_id=client_id,
                client_secret=client_secret,
                refresh_token=refresh_token,
            )
    return None
