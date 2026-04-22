"""Tests for freeotp_vault.parser."""

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
        assert t["secret"]

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
        payload = json.dumps([
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
        ])
        tokens = parse_freeotp_json(payload)
        assert len(tokens) == 1

    def test_defaults_applied(self):
        payload = json.dumps({
            "tokens": [{
                "label": "minimal",
                "secret": "JBSWY3DPEHPK3PXP",
            }]
        })
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
        payload = json.dumps({"tokens": [{
            "label": "neg",
            "secret": [-128, -1, -64],
            "type": "TOTP",
            "algo": "SHA1",
            "digits": 6,
            "period": 30,
            "counter": 0,
        }]})
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["secret"]

    def test_unsupported_type_defaults_to_totp(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "type": "STEAM",
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["type"] == "TOTP"

    def test_multiple_tokens(self):
        payload = json.dumps({
            "tokens": [
                {"label": f"acc{i}", "secret": "JBSWY3DPEHPK3PXP"} for i in range(5)
            ]
        })
        tokens = parse_freeotp_json(payload)
        assert len(tokens) == 5


class TestParserEdgeCases:
    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_freeotp_json("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_freeotp_json("   \n\t  ")

    def test_digits_zero(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "digits": 0,
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["digits"] == 0

    def test_digits_very_large(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "digits": 20,
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["digits"] == 20

    def test_period_very_large(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "period": 300,
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["period"] == 300

    def test_counter_very_large(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "type": "HOTP",
                "counter": 999999999,
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["counter"] == 999999999

    def test_secret_with_padding(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP====",
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["secret"]

    def test_secret_lowercase(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "jbswy3dpehpk3pxp",
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["secret"]

    def test_issuer_account_name_only(self):
        payload = json.dumps({
            "tokens": [{
                "issuer": "Test",
                "accountName": "user",
                "secret": "JBSWY3DPEHPK3PXP",
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["issuer"] == "Test"
        assert tokens[0]["label"] == "user"

    def test_sha512_algorithm(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "algorithm": "SHA512",
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["algo"] == "SHA512"

    def test_token_order_field_ignored(self):
        payload = json.dumps({
            "tokenOrder": ["0", "1"],
            "tokens": [
                {"label": "a", "secret": "JBSWY3DPEHPK3PXP"},
                {"label": "b", "secret": "JBSWY3DPEHPK3PXP"},
            ]
        })
        tokens = parse_freeotp_json(payload)
        assert len(tokens) == 2


class TestParserAdversarial:
    def test_invalid_json_array_items(self):
        with pytest.raises(ValueError, match="not an object"):
            parse_freeotp_json(json.dumps({"tokens": ["not an object"]}))

    def test_secret_number_raises(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": 12345,
            }]
        })
        with pytest.raises(ValueError, match="Unrecognised secret type"):
            parse_freeotp_json(payload)

    def test_secret_dict_raises(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": {"bad": "format"},
            }]
        })
        with pytest.raises(ValueError, match="Unrecognised secret type"):
            parse_freeotp_json(payload)

    def test_missing_tokens_key_in_dict(self):
        payload = json.dumps({"other": "data"})
        with pytest.raises(ValueError, match="No tokens"):
            parse_freeotp_json(payload)

    def test_tokens_not_a_list(self):
        payload = json.dumps({"tokens": "not a list"})
        with pytest.raises(ValueError, match="not a list"):
            parse_freeotp_json(payload)

    def test_empty_secret_array(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": [],
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["secret"] == ""

    def test_secret_mixed_case_base32(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JaBsWy3DpEhPk3PxP",
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["secret"]

    def test_digit_non_integer_string(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "digits": "6",
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["digits"] == 6

    def test_negative_counter(self):
        payload = json.dumps({
            "tokens": [{
                "label": "x",
                "secret": "JBSWY3DPEHPK3PXP",
                "type": "HOTP",
                "counter": -1,
            }]
        })
        tokens = parse_freeotp_json(payload)
        assert tokens[0]["counter"] == -1