"""
OTP token generation (TOTP and HOTP) backed by pyotp.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pyotp

if TYPE_CHECKING:
    from .parser import Token


def generate_token(token: Token) -> str:
    """Generate the current OTP code for *token*.

    For TOTP returns the code valid at the current time.
    For HOTP returns the code for the stored counter (does NOT increment;
    the caller is responsible for persisting the updated counter).

    Args:
        token: Normalised token dict as produced by :func:`parse_freeotp_json`.

    Returns:
        Zero-padded OTP string (length == token["digits"]).

    Raises:
        ValueError: On unsupported token type or malformed secret.
    """
    secret = token["secret"]
    digits = int(token.get("digits", 6))
    algo = token.get("algo", "SHA1").upper()
    digest_map = {"SHA1": "sha1", "SHA256": "sha256", "SHA512": "sha512"}
    digest = digest_map.get(algo, "sha1")

    token_type = token.get("type", "TOTP").upper()


    if token_type == "TOTP":
        period = int(token.get("period", 30))
        totp = pyotp.TOTP(secret, digits=digits, digest=digest, interval=period)
        return totp.now()

    if token_type == "HOTP":
        counter = int(token.get("counter", 0))
        hotp = pyotp.HOTP(secret, digits=digits, digest=digest)
        return hotp.at(counter)

    raise ValueError(f"Unsupported token type: {token_type!r}")


def seconds_remaining(token: Token) -> int:
    """Return seconds until the current TOTP window expires.

    Returns 0 for HOTP tokens (counter-based, no expiry).
    """
    if token.get("type", "TOTP").upper() != "TOTP":
        return 0
    period = int(token.get("period", 30))
    return period - (int(time.time()) % period)
