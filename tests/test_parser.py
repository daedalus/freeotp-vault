"""Tests for freeotp_vault.parser."""

import base64
import json

import pytest

from freeotp_vault.parser import parse_freeotp_json


class TestParseFreeotp:
    def test_original_int8_array(self, freeotp_json_bytes):
        tokens = parse_freeotp_json(freeotp_json_bytes)
        assert len(tokens) == 1
        t = tokens[0]
        assert t["issuer"] == "GitHub"
        assert t["label"] == "alice@example.com"
        assert t["type"] == "TOTP"
        assert t["algo"] == "SHA1"
        assert t["digits"] == 6
        assert t["period"] == 30
        # Secret should decode correctly
        decoded = base64.b32decode(t["secret"] + "=" * ((8 - len(t["secret"]) % 8) % 8))
        assert len(decoded) > 0

    def test_plus_base32_string(self, freeotp_plus_json):
        tokens = parse_freeotp_json(freeotp_plus_json)
        assert len(tokens) == 1
        t = tokens[0]
        assert t["issuer"] == "Acme"
        assert t["type"] == "HOTP"
        assert t["algo"] == "SHA256"
        assert t["digits"] == 8
        assert t["counter"] == 3

    def test_bare_list_format(self):
        payload = json.dumps(
            [
                {
                    "issuerExt": "Test",
                    "label": "user",
                    "secret": "JBSWY3DPEHPK3PXP",
                    "type": "TOTP",
                    "algo": "SHA1",
                    "digits": 6,
                    "period": 30,
                    "counter": 0,
                }
            ]
        )
        tokens = parse_freeotp_json(payload)
        assert len(tokens) == 1

    def test_defaults_applied(self):
        payload = json.dumps(
            {
                "tokens": [
                    {
                        "label": "minimal",
                        "secret": "JBSWY3DPEHPK3PXP",
                    }
                ]
            }
        )
        tokens = parse_freeotp_json(payload)
        t = tokens[0]
        assert t["type"] == "TOTP"
        assert t["algo"] == "SHA1"
        assert t["digits"] == 6
        assert t["period"] == 30
        assert t["counter"] == 0

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_freeotp_json("{not json}")

    def test_empty_tokens_list_raises(self):
        with pytest.raises(ValueError, match="No tokens"):
            parse_freeotp_json(json.dumps({"tokens": []}))

    def test_missing_secret_raises(self):
        payload = json.dumps({"tokens": [{"label": "x"}]})
        with pytest.raises(ValueError, match="missing 'secret'"):
            parse_freeotp_json(payload)

    def test_invalid_base32_raises(self):
        payload = json.dumps({"tokens": [{"label": "x", "secret": "!!!NOTBASE32!!!"}]})
        with pytest.raises(ValueError, match="base32"):
            parse_freeotp_json(payload)

    def test_signed_bytes_negative_values(self):
        # All negative: -128..−1 → 128..255
        payload = json.dumps(
            {
                "tokens": [
                    {
                        "label": "neg",
                        "secret": [-128, -1, -64],
                        "type": "TOTP",
                        "algo": "SHA1",
                        "digits": 6,
                        "period": 30,
                        "counter": 0,
                    }
                ]
            }
        )
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["secret"]  # should not raise

    def test_unsupported_type_defaults_to_totp(self):
        payload = json.dumps(
            {
                "tokens": [
                    {
                        "label": "x",
                        "secret": "JBSWY3DPEHPK3PXP",
                        "type": "STEAM",
                    }
                ]
            }
        )
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["type"] == "TOTP"

    def test_multiple_tokens(self):
        payload = json.dumps(
            {
                "tokens": [
                    {"label": f"acc{i}", "secret": "JBSWY3DPEHPK3PXP"} for i in range(5)
                ]
            }
        )
        tokens = parse_freeotp_json(payload)
        assert len(tokens) == 5
