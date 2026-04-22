"""Tests for freeotp_vault.crypto."""

import pytest

from freeotp_vault.crypto import decrypt_vault, encrypt_vault


class TestEncryptDecrypt:
    def test_roundtrip(self):
        data = b'[{"issuer":"Test","secret":"ABC"}]'
        blob = encrypt_vault(data, "hunter2")
        assert decrypt_vault(blob, "hunter2") == data

    def test_magic_bytes_present(self):
        blob = encrypt_vault(b"hello", "pw")
        assert blob[:4] == b"FOTV"

    def test_version_byte(self):
        blob = encrypt_vault(b"hello", "pw")
        assert blob[4] == 0x01

    def test_wrong_password_raises(self):
        blob = encrypt_vault(b"secret", "correct")
        with pytest.raises(ValueError, match="Wrong password"):
            decrypt_vault(blob, "wrong")

    def test_truncated_blob_raises(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt_vault(b"FOTV\x01" + b"\x00" * 10, "pw")

    def test_bad_magic_raises(self):
        blob = encrypt_vault(b"data", "pw")
        corrupted = b"XXXX" + blob[4:]
        with pytest.raises(ValueError, match="bad magic"):
            decrypt_vault(corrupted, "pw")

    def test_bad_version_raises(self):
        blob = encrypt_vault(b"data", "pw")
        corrupted = blob[:4] + bytes([0xFF]) + blob[5:]
        with pytest.raises(ValueError, match="Unsupported vault version"):
            decrypt_vault(corrupted, "pw")

    def test_each_encrypt_produces_unique_blob(self):
        data = b"same data"
        b1 = encrypt_vault(data, "pw")
        b2 = encrypt_vault(data, "pw")
        # Different salt/nonce each time
        assert b1 != b2

    def test_empty_plaintext_roundtrip(self):
        blob = encrypt_vault(b"", "pw")
        assert decrypt_vault(blob, "pw") == b""

    def test_large_plaintext_roundtrip(self):
        data = b"x" * 100_000
        blob = encrypt_vault(data, "longpassword!")
        assert decrypt_vault(blob, "longpassword!") == data

    def test_unicode_password(self):
        data = b"unicode test"
        blob = encrypt_vault(data, "pässwörð")
        assert decrypt_vault(blob, "pässwörð") == data

    def test_bit_flip_detected(self):
        blob = encrypt_vault(b"important", "pw")
        # Flip a bit in the ciphertext body
        lst = bytearray(blob)
        lst[-1] ^= 0x01
        with pytest.raises(ValueError):
            decrypt_vault(bytes(lst), "pw")
