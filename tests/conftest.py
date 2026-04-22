"""Configure pytest to find the src package."""

import base64
import json
import sys
from pathlib import Path

import pytest

src_path = Path(__file__).parent.parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

TOTP_TOKEN = {
    "issuer": "GitHub",
    "label": "alice@example.com",
    "secret": "JBSWY3DPEHPK3PXP",
    "type": "TOTP",
    "algo": "SHA1",
    "digits": 6,
    "period": 30,
    "counter": 0,
}

HOTP_TOKEN = {
    "issuer": "Acme",
    "label": "bob@acme.com",
    "secret": "JBSWY3DPEHPK3PXP",
    "type": "HOTP",
    "algo": "SHA1",
    "digits": 6,
    "period": 30,
    "counter": 5,
}


@pytest.fixture
def totp_token() -> dict:
    return dict(TOTP_TOKEN)


@pytest.fixture
def hotp_token() -> dict:
    return dict(HOTP_TOKEN)


@pytest.fixture
def token_list() -> list[dict]:
    return [dict(TOTP_TOKEN), dict(HOTP_TOKEN)]


@pytest.fixture
def freeotp_json_bytes() -> str:
    """A minimal FreeOTP original JSON export (secret as int8 array)."""
    secret_bytes = base64.b32decode("JBSWY3DPEHPK3PXP====")
    signed = [b if b < 128 else b - 256 for b in secret_bytes]
    payload = {
        "tokens": [
            {
                "issuerExt": "GitHub",
                "label": "alice@example.com",
                "secret": signed,
                "type": "TOTP",
                "algo": "SHA1",
                "digits": 6,
                "period": 30,
                "counter": 0,
            }
        ]
    }
    return json.dumps(payload)


@pytest.fixture
def freeotp_plus_json() -> str:
    """FreeOTP+ JSON with base32 string secret."""
    payload = {
        "tokenOrder": ["0"],
        "tokens": [
            {
                "issuer": "Acme",
                "label": "bob@acme.com",
                "secret": "JBSWY3DPEHPK3PXP",
                "type": "HOTP",
                "algo": "SHA256",
                "digits": 8,
                "period": 30,
                "counter": 3,
            }
        ],
    }
    return json.dumps(payload)