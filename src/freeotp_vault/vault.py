"""
High-level vault operations: load, save, query, mutate.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .crypto import decrypt_vault, encrypt_vault

if TYPE_CHECKING:
    from .parser import GdriveAuthData, Token

from .parser import Token  # noqa: TC001  # type: ignore[attr-defined]

DEFAULT_VAULT_DIR = Path.home() / ".config" / "freeotp-vault"
DEFAULT_VAULT_PATH = DEFAULT_VAULT_DIR / "vault.enc"


class VaultData(dict):  # type: ignore[type-arg]
    """Vault dict containing tokens and optional gdrive_auth."""

    tokens: list[Token]
    gdrive_auth: GdriveAuthData | None


def _vault_path(path: str | Path | None) -> Path:
    return Path(path) if path else DEFAULT_VAULT_PATH


def _hash_file(path: Path) -> Path:
    """Return the hash file path for a given vault path."""
    return path.with_suffix(".sha.txt")


def compute_vault_hash(plaintext: bytes) -> str:
    """Compute SHA256 hash of vault plaintext (JSON bytes)."""
    return hashlib.sha256(plaintext).hexdigest()


def _save_hash(vault_path: Path, content_hash: str) -> None:
    """Save hash to .sha.txt file."""
    hash_path = _hash_file(vault_path)
    hash_path.write_text(content_hash + "\n", encoding="utf-8")
    os.chmod(hash_path, 0o600)


def _load_hash(vault_path: Path) -> str | None:
    """Load hash from .sha.txt file. Returns None if missing."""
    hash_path = _hash_file(vault_path)
    if hash_path.exists():
        return hash_path.read_text(encoding="utf-8").strip()
    return None


def vault_exists(path: str | Path | None = None) -> bool:
    """Return True if the vault file exists on disk."""
    return _vault_path(path).exists()


def _raw_to_vault(
    raw: bytes, password: str, vault_path: Path, verify_integrity: bool = True
) -> VaultData:
    plaintext = decrypt_vault(raw, password)
    content_hash = compute_vault_hash(plaintext)

    if verify_integrity:
        stored_hash = _load_hash(vault_path)
        if stored_hash is not None and stored_hash != content_hash:
            raise ValueError(
                "Vault integrity check failed: hash mismatch. "
                "The vault may have been tampered with or corrupted."
            )

    obj = json.loads(plaintext.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Vault format error: expected dict with 'tokens' key.")
    if "tokens" not in obj:
        raise ValueError("Vault format error: missing 'tokens' key.")
    vault: VaultData = VaultData(obj)
    if vault.get("gdrive_auth") is None:
        vault["gdrive_auth"] = None
    return vault


def load_vault(password: str, path: str | Path | None = None) -> VaultData:
    """Load and decrypt the vault.

    Args:
        password: Vault unlock password.
        path: Optional override for vault file location.

    Returns:
        VaultData dict with 'tokens' and optional 'gdrive_auth'.

    Raises:
        FileNotFoundError: If vault file does not exist.
        ValueError: On wrong password, corruption, or integrity failure.
    """
    vp = _vault_path(path)
    if not vp.exists():
        raise FileNotFoundError(
            f"Vault not found at {vp}. Run `freeotp-vault init <json_file>` first."
        )
    return _raw_to_vault(vp.read_bytes(), password, vp)


def save_vault(
    tokens: list[Token],
    password: str,
    path: str | Path | None = None,
    gdrive_auth: GdriveAuthData | None = None,
) -> None:
    """Encrypt and persist tokens (and gdrive_auth) to the vault file.

    Args:
        tokens: List of normalised token dicts.
        password: Encryption password.
        path: Optional override for vault file location.
        gdrive_auth: Optional gdrive auth data to store.
    """
    vp = _vault_path(path)
    vp.parent.mkdir(parents=True, exist_ok=True)
    vault: VaultData = VaultData({"tokens": tokens})
    if gdrive_auth:
        vault["gdrive_auth"] = gdrive_auth
    plaintext = json.dumps(vault, separators=(",", ":")).encode("utf-8")
    content_hash = compute_vault_hash(plaintext)
    blob = encrypt_vault(plaintext, password)
    tmp = vp.with_suffix(".tmp")
    tmp.write_bytes(blob)
    tmp.replace(vp)
    os.chmod(vp, 0o600)
    _save_hash(vp, content_hash)


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
    vault = load_vault(password, path)
    return cast("list[Token]", vault["tokens"])


def save_tokens(
    tokens: list[Token], password: str, path: str | Path | None = None
) -> None:
    """Encrypt and persist the token list to the vault file.

    Args:
        tokens: List of normalised token dicts.
        password: Encryption password.
        path: Optional override for vault file location.
    """
    save_vault(tokens, password, path)


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
