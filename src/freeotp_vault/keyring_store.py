"""
System keyring integration for vault password storage.

Service name: "freeotp-vault"
Username:     absolute path of the vault file (allows multiple vaults)
"""

from __future__ import annotations

import sys

SERVICE = "freeotp-vault"


def get_password_from_keyring(vault_path: str) -> str | None:
    """Retrieve the stored vault password from the OS keyring.

    Args:
        vault_path: Absolute path to the vault file (used as username key).

    Returns:
        Password string if found, None otherwise.
    """
    try:
        import keyring

        return keyring.get_password(SERVICE, vault_path)
    except Exception:
        return None


def store_password_in_keyring(vault_path: str, password: str) -> bool:
    """Store *password* in the OS keyring.

    Args:
        vault_path: Absolute path to the vault file.
        password: Password to store.

    Returns:
        True on success, False if keyring is unavailable.
    """
    try:
        import keyring

        keyring.set_password(SERVICE, vault_path, password)
        return True
    except Exception as exc:
        print(
            f"  [warn] Could not save to keyring: {exc}",
            file=sys.stderr,
        )
        return False


def delete_password_from_keyring(vault_path: str) -> None:
    """Remove stored password entry from the OS keyring (best-effort)."""
    try:
        import keyring

        keyring.delete_password(SERVICE, vault_path)
    except Exception:
        pass
