"""
High-level vault operations: load, save, query, mutate.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .crypto import decrypt_vault, encrypt_vault
from .parser import Token

DEFAULT_VAULT_DIR = Path.home() / ".config" / "freeotp-vault"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"


def _vault_path(path: str | Path | None) -> Path:
    return Path(path) if path else DEFAULT_VAULT_PATH


def vault_exists(path: str | Path | None = None) -> bool:
    """Return True if the vault file exists on disk."""
    return _vault_path(path).exists()


def load_tokens(password: str, path: str | Path | None = None) -> list[Token]:
    """Load and decrypt the vault, returning the token list.

    Args:
        password: Vault unlock password.
        path: Optional override for vault file location.

    Returns:
        List of normalised token dicts.

    Raises:
        FileNotFoundError: If vault file does not exist.
        ValueError: On wrong password or corruption.
    """
    vp = _vault_path(path)
    if not vp.exists():
        raise FileNotFoundError(
            f"Vault not found at {vp}. Run `freeotp-vault init <json_file>` first."
        )
    blob = vp.read_bytes()
    plaintext = decrypt_vault(blob, password)
    return json.loads(plaintext.decode("utf-8"))  # type: ignore[no-any-return]


def save_tokens(
    tokens: list[Token], password: str, path: str | Path | None = None
) -> None:
    """Encrypt and persist the token list to the vault file.

    Args:
        tokens: List of normalised token dicts.
        password: Encryption password.
        path: Optional override for vault file location.
    """
    vp = _vault_path(path)
    vp.parent.mkdir(parents=True, exist_ok=True)
    plaintext = json.dumps(tokens, separators=(",", ":")).encode("utf-8")
    blob = encrypt_vault(plaintext, password)
    tmp = vp.with_suffix(".tmp")
    tmp.write_bytes(blob)
    tmp.replace(vp)
    os.chmod(vp, 0o600)


def filter_tokens(tokens: list[Token], query: str | None) -> list[Token]:
    """Return tokens whose issuer or label contains *query* (case-insensitive).

    If *query* is None or empty, all tokens are returned.
    """
    if not query:
        return tokens
    q = query.lower()
    return [
        t
        for t in tokens
        if q in t.get("issuer", "").lower() or q in t.get("label", "").lower()
    ]
