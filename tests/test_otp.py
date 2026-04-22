"""Tests for freeotp_vault.otp."""

import time

import pyotp
import pytest

from freeotp_vault.otp import generate_token, seconds_remaining


class TestGenerateToken:
    def test_totp_matches_pyotp(self, totp_token):
        expected = pyotp.TOTP(totp_token["secret"]).now()
        assert generate_token(totp_token) == expected

    def test_hotp_matches_pyotp(self, hotp_token):
        expected = pyotp.HOTP(hotp_token["secret"]).at(hotp_token["counter"])
        assert generate_token(hotp_token) == expected

    def test_totp_is_digits_long(self, totp_token):
        code = generate_token(totp_token)
        assert len(code) == totp_token["digits"]

    def test_hotp_is_digits_long(self, hotp_token):
        code = generate_token(hotp_token)
        assert len(code) == hotp_token["digits"]

    def test_totp_8_digits(self, totp_token):
        t = dict(totp_token, digits=8)
        code = generate_token(t)
        assert len(code) == 8

    def test_totp_sha256(self, totp_token):
        t = dict(totp_token, algo="SHA256")
        expected = pyotp.TOTP(t["secret"], digest="sha256").now()
        assert generate_token(t) == expected

    def test_totp_sha512(self, totp_token):
        t = dict(totp_token, algo="SHA512")
        expected = pyotp.TOTP(t["secret"], digest="sha512").now()
        assert generate_token(t) == expected

    def test_hotp_counter_zero(self, hotp_token):
        t = dict(hotp_token, counter=0)
        expected = pyotp.HOTP(t["secret"]).at(0)
        assert generate_token(t) == expected

    def test_unsupported_type_raises(self, totp_token):
        t = dict(totp_token, type="STEAM")
        with pytest.raises(ValueError, match="Unsupported token type"):
            generate_token(t)

    def test_totp_returns_string(self, totp_token):
        assert isinstance(generate_token(totp_token), str)

    def test_totp_is_numeric(self, totp_token):
        code = generate_token(totp_token)
        assert code.isdigit()


class TestSecondsRemaining:
    def test_totp_range(self, totp_token):
        secs = seconds_remaining(totp_token)
        assert 0 <= secs <= 30

    def test_totp_custom_period(self, totp_token):
        t = dict(totp_token, period=60)
        secs = seconds_remaining(t)
        assert 0 <= secs <= 60

    def test_hotp_returns_zero(self, hotp_token):
        assert seconds_remaining(hotp_token) == 0

    def test_within_expected_window(self, totp_token):
        period = totp_token["period"]
        secs = seconds_remaining(totp_token)
        expected = period - (int(time.time()) % period)
        assert abs(secs - expected) <= 1


class TestOTPEdgeCases:
    def test_totp_digit_1(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "TOTP", "digits": 1}
        code = generate_token(t)
        assert len(code) == 1

    def test_totp_digit_8(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "TOTP", "digits": 8}
        code = generate_token(t)
        assert len(code) == 8

    def test_totp_period_15(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "TOTP", "period": 15}
        code = generate_token(t)
        assert code

    def test_totp_period_60(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "TOTP", "period": 60}
        code = generate_token(t)
        assert code

    def test_hotp_large_counter(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "HOTP", "counter": 1000000}
        code = generate_token(t)
        assert code

    def test_totp_case_insensitive_algo(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "TOTP", "algo": "sha1"}
        code = generate_token(t)
        assert code

    def test_hotp_digit_8(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "HOTP", "digits": 8}
        code = generate_token(t)
        assert len(code) == 8

    def test_seconds_remaining_hotp_type(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "Hotp"}
        assert seconds_remaining(t) == 0


class TestOTPAdversarial:
    def test_malformed_secret(self):
        t = {"secret": "NOT-VALID-B32!", "type": "TOTP"}
        with pytest.raises(Exception):
            generate_token(t)

    def test_empty_secret(self):
        t = {"secret": "", "type": "TOTP"}
        code = generate_token(t)
        assert code

    def test_unknown_algo(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "TOTP", "algo": "MD5"}
        code = generate_token(t)
        assert code

    def test_large_counter(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "HOTP", "counter": 1000000}
        code = generate_token(t)
        assert code

    def test_missing_type(self):
        t = {"secret": "JBSWY3DPEHPK3PXP"}
        code = generate_token(t)
        assert code

    def test_seconds_missing_type(self):
        t = {"secret": "JBSWY3DPEHPK3PXP"}
        secs = seconds_remaining(t)
        assert 0 <= secs <= 30

    def test_seconds_type_string(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "TOTP"}
        secs = seconds_remaining(t)
        assert 0 <= secs <= 30

    def test_hotp_type_uppercase(self):
        t = {"secret": "JBSWY3DPEHPK3PXP", "type": "HOTP"}
        code = generate_token(t)
        assert code

    def test_very_long_secret(self):
        # Use 32 bytes of base32-compatible data
        long_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        t = {"secret": long_secret, "type": "TOTP"}
        code = generate_token(t)
        assert code
