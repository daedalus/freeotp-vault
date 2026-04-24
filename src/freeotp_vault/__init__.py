"""freeotp-vault — encrypted CLI OTP vault for FreeOTP JSON exports."""

from typing import TYPE_CHECKING

from .crypto import decrypt_vault, encrypt_vault
from .gdrive import gdrive_logout, gdrive_sync
from .keyring_store import (
    delete_password_from_keyring,
    get_password_from_keyring,
    store_password_in_keyring,
)
from .otp import generate_token, seconds_remaining
from .parser import Token, parse_freeotp_json
from .vault import filter_tokens, load_tokens, save_tokens, vault_exists

__version__ = "0.1.3"
__all__ = [
    "encrypt_vault",
    "decrypt_vault",
    "parse_freeotp_json",
    "generate_token",
    "seconds_remaining",
    "get_password_from_keyring",
    "store_password_in_keyring",
    "delete_password_from_keyring",
    "vault_exists",
    "load_tokens",
    "save_tokens",
    "filter_tokens",
    "Token",
    "gdrive_sync",
    "gdrive_logout",
]

if TYPE_CHECKING:
    from .cli import main
