"""
Vault encryption/decryption using AES-256-GCM with scrypt key derivation.

Binary layout of an encrypted vault blob:
  [4 B]  magic  = b"FOTV"
  [1 B]  version = 0x01
  [32 B] scrypt salt
  [12 B] AES-GCM nonce
  [N  B] ciphertext + 16-byte GCM tag (appended by GCM)
"""

from __future__ import annotations

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"FOTV"
VERSION = 0x01
SALT_LEN = 32
NONCE_LEN = 12
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN  # 49


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from *password* using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt_vault(data: bytes, password: str) -> bytes:
    """AES-256-GCM encrypt *data* with a scrypt-derived key.

    Args:
        data: Plaintext bytes (UTF-8 JSON of token list).
        password: User-supplied password string.

    Returns:
        Binary blob (magic + version + salt + nonce + ciphertext+tag).
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # tag appended by GCM
    return MAGIC + struct.pack("B", VERSION) + salt + nonce + ciphertext


def decrypt_vault(blob: bytes, password: str) -> bytes:
    """Decrypt an AES-256-GCM vault blob.

    Args:
        blob: Binary blob produced by :func:`encrypt_vault`.
        password: Password to unlock the vault.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If the magic bytes are wrong, the version is unsupported,
                    the blob is truncated, or the password/tag is invalid.
    """
    if len(blob) < HEADER_LEN + 16:  # 16 = minimum GCM tag
        raise ValueError("Vault blob too short — file may be corrupted.")

    if blob[:4] != MAGIC:
        raise ValueError("Not a freeotp-vault file (bad magic bytes).")

    version = struct.unpack("B", blob[4:5])[0]
    if version != VERSION:
        raise ValueError(f"Unsupported vault version: {version}.")

    salt = blob[5 : 5 + SALT_LEN]
    nonce = blob[5 + SALT_LEN : 5 + SALT_LEN + NONCE_LEN]
    ciphertext = blob[HEADER_LEN:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Wrong password or vault is corrupted.")
