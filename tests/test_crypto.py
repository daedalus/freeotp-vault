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
        lst = bytearray(blob)
        lst[-1] ^= 0x01
        with pytest.raises(ValueError):
            decrypt_vault(bytes(lst), "pw")


class TestCryptoEdgeCases:
    def test_single_byte_plaintext(self):
        data = b"x"
        blob = encrypt_vault(data, "pw")
        assert decrypt_vault(blob, "pw") == data

    def test_binary_data_roundtrip(self):
        data = bytes(range(256))
        blob = encrypt_vault(data, "pw")
        assert decrypt_vault(blob, "pw") == data

    def test_null_bytes_roundtrip(self):
        data = b"\x00\x00\x00"
        blob = encrypt_vault(data, "pw")
        assert decrypt_vault(blob, "pw") == data

    def test_json_special_chars_roundtrip(self):
        data = b'{"key":"value with \\"quotes\\" and \n newline"}'
        blob = encrypt_vault(data, "pw")
        assert decrypt_vault(blob, "pw") == data


class TestCryptoAdversarial:
    def test_random_bytes_not_decryptable(self):
        import os

        random_data = os.urandom(100)
        with pytest.raises(ValueError):
            decrypt_vault(random_data, "anypassword")

    def test_garbage_after_valid_header(self):
        blob = encrypt_vault(b"data", "pw")
        garbage = blob[:50] + b"\x00" * 100
        with pytest.raises(ValueError):
            decrypt_vault(garbage, "pw")

    def test_truncated_at_header(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt_vault(b"FOTV", "pw")

    def test_truncated_at_salt(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt_vault(b"FOTV\x01" + b"\x00" * 30, "pw")

    def test_truncated_at_nonce(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt_vault(b"FOTV\x01" + b"\x00" * 45, "pw")

    def test_altered_salt(self):
        blob = encrypt_vault(b"secret", "pw")
        lst = bytearray(blob)
        lst[10] ^= 0xFF
        with pytest.raises(ValueError):
            decrypt_vault(bytes(lst), "pw")

    def test_altered_nonce(self):
        blob = encrypt_vault(b"secret", "pw")
        lst = bytearray(blob)
        lst[42] ^= 0xFF
        with pytest.raises(ValueError):
            decrypt_vault(bytes(lst), "pw")

    def test_empty_password(self):
        data = b"test"
        blob = encrypt_vault(data, "")
        assert decrypt_vault(blob, "") == data

    def test_extremely_long_password(self):
        data = b"test"
        long_pw = "a" * 10000
        blob = encrypt_vault(data, long_pw)
        assert decrypt_vault(blob, long_pw) == data

    def test_all_printable_chars_password(self):
        data = b"test"
        pw = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
        blob = encrypt_vault(data, pw)
        assert decrypt_vault(blob, pw) == data

    def test_alternate_version_number(self):
        blob = encrypt_vault(b"data", "pw")
        corrupted = blob[:4] + bytes([0x02]) + blob[5:]
        with pytest.raises(ValueError, match="Unsupported vault version"):
            decrypt_vault(corrupted, "pw")
