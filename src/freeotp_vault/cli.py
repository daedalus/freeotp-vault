"""
freeotp-vault — command-line OTP vault for FreeOTP JSON exports.

Usage:
  freeotp-vault init <json_file>          Import + encrypt a FreeOTP export
  freeotp-vault list [--filter TEXT]      List stored accounts
  freeotp-vault token [--filter TEXT]     Generate OTP codes
  freeotp-vault change-password           Re-encrypt with a new password
  freeotp-vault remove --filter TEXT      Remove matching accounts
  freeotp-vault gdrive-sync [--download | --upload]  Sync with Google Drive
  freeotp-vault gdrive-logout              Remove Google Drive credentials
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .gdrive import gdrive_logout, gdrive_sync
from .keyring_store import (
    delete_password_from_keyring,
    get_password_from_keyring,
    store_password_in_keyring,
)
from .otp import generate_token, seconds_remaining
from .parser import Token, parse_freeotp_json
from .vault import (
    DEFAULT_VAULT_PATH,
    filter_tokens,
    load_tokens,
    save_tokens,
    vault_exists,
)


def _die(msg: str, code: int = 1) -> None:
    """Print error message and exit."""
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def _ask_new_password(prompt: str = "New vault password") -> str:
    while True:
        pw = getpass.getpass(f"{prompt}: ")
        if not pw:
            print("Password must not be empty. Try again.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if pw == confirm:
            return pw
        print("Passwords do not match. Try again.")


def _unlock(vault_path: Path) -> tuple[str, list[Token]]:
    abs_path = str(vault_path.resolve())

    password = get_password_from_keyring(abs_path)
    if password:
        try:
            tokens = load_tokens(password, vault_path)
            return password, tokens
        except ValueError:
            print("[warn] Keyring password no longer valid. Please re-enter.")
            delete_password_from_keyring(abs_path)

    for attempt in range(3):
        password = getpass.getpass(f"Vault password (attempt {attempt + 1}/3): ")
        try:
            tokens = load_tokens(password, vault_path)
            try:
                save = input("Save password to system keyring? [y/N] ").strip().lower()
            except EOFError:
                save = "n"
            if save == "y":
                if store_password_in_keyring(abs_path, password):
                    print("  Password stored in keyring.")
                else:
                    print("  Keyring unavailable; password NOT stored.")
            return password, tokens
        except ValueError as exc:
            print(f"  {exc}")

    _die("Too many failed attempts.")
    # mypy thinks we can reach here after _die, but _die calls sys.exit
    assert False, "unreachable"


def cmd_init(args: argparse.Namespace) -> None:
    json_path = Path(args.json_file)
    if not json_path.exists():
        _die(f"File not found: {json_path}")

    vault_path = Path(args.vault) if args.vault else DEFAULT_VAULT_PATH

    if vault_exists(vault_path):
        try:
            confirm = (
                input(f"Vault already exists at {vault_path}. Overwrite? [y/N] ")
                .strip()
                .lower()
            )
        except EOFError:
            confirm = "n"
        if confirm != "y":
            print("Aborted.")
            return

    raw = json_path.read_text(encoding="utf-8")
    try:
        tokens = parse_freeotp_json(raw)
    except ValueError as exc:
        _die(f"Could not parse FreeOTP export: {exc}")

    print(f"Found {len(tokens)} token(s). Creating encrypted vault...")
    password = _ask_new_password()
    save_tokens(tokens, password, vault_path)
    print(f"Vault created: {vault_path}")

    abs_path = str(vault_path.resolve())
    try:
        save_kr = input("Save password to system keyring? [y/N] ").strip().lower()
    except EOFError:
        save_kr = "n"
    if save_kr == "y":
        if store_password_in_keyring(abs_path, password):
            print("  Password stored in keyring.")
        else:
            print("  Keyring unavailable; password NOT stored.")


def cmd_list(args: argparse.Namespace) -> None:
    vault_path = Path(args.vault) if args.vault else DEFAULT_VAULT_PATH
    if not vault_exists(vault_path):
        _die(f"Vault not found at {vault_path}. Run `init` first.")

    _, tokens = _unlock(vault_path)
    matches = filter_tokens(tokens, args.filter)

    if not matches:
        print("No accounts match the filter.")
        return

    print(
        f"\n{'#':<4}  {'ISSUER':<20}  {'LABEL':<30}  {'TYPE':<5}  {'ALGO':<6}  DIGITS"
    )
    print("-" * 72)
    for i, t in enumerate(matches, 1):
        print(
            f"{i:<4}  {t['issuer']:<20}  {t['label']:<30}  "
            f"{t['type']:<5}  {t['algo']:<6}  {t['digits']}"
        )
    print(f"\nTotal: {len(matches)} account(s).\n")


def cmd_token(args: argparse.Namespace) -> None:
    vault_path = Path(args.vault) if args.vault else DEFAULT_VAULT_PATH
    if not vault_exists(vault_path):
        _die(f"Vault not found at {vault_path}. Run `init` first.")

    _, tokens = _unlock(vault_path)
    matches = filter_tokens(tokens, args.filter)

    if not matches:
        print("No accounts match the filter.")
        return

    print(f"\n{'ISSUER':<20}  {'LABEL':<30}  {'CODE':<8}  {'EXPIRES IN':>12}")
    print("-" * 76)

    for t in matches:
        try:
            code = generate_token(t)
        except Exception as exc:
            code = f"ERROR:{exc}"

        if t["type"].upper() == "TOTP":
            secs = seconds_remaining(t)
            expiry = f"{secs:>3}s"
        else:
            expiry = f"ctr={t['counter']}"

        print(f"{t['issuer']:<20}  {t['label']:<30}  {code:<8}  {expiry:>12}")

    print()


def cmd_change_password(args: argparse.Namespace) -> None:
    vault_path = Path(args.vault) if args.vault else DEFAULT_VAULT_PATH
    if not vault_exists(vault_path):
        _die(f"Vault not found at {vault_path}. Run `init` first.")

    _, tokens = _unlock(vault_path)
    print("Vault unlocked. Enter a new password.")
    new_password = _ask_new_password("New vault password")
    save_tokens(tokens, new_password, vault_path)

    abs_path = str(vault_path.resolve())
    delete_password_from_keyring(abs_path)
    store_password_in_keyring(abs_path, new_password)
    print("Password changed and vault re-encrypted.")
    print("Keyring entry updated.")


def cmd_remove(args: argparse.Namespace) -> None:
    if not args.filter:
        _die("--filter is required for the remove command.")

    vault_path = Path(args.vault) if args.vault else DEFAULT_VAULT_PATH
    if not vault_exists(vault_path):
        _die(f"Vault not found at {vault_path}. Run `init` first.")

    password, tokens = _unlock(vault_path)
    matches = filter_tokens(tokens, args.filter)

    if not matches:
        print("No accounts match the filter.")
        return

    print(f"Accounts to remove ({len(matches)}):")
    for t in matches:
        print(f"  • {t['issuer']} / {t['label']}")

    try:
        confirm = input("Confirm removal? [y/N] ").strip().lower()
    except EOFError:
        confirm = "n"

    if confirm != "y":
        print("Aborted.")
        return

    remaining = [t for t in tokens if t not in matches]
    save_tokens(remaining, password, vault_path)
    print(f"Removed {len(matches)} account(s). {len(remaining)} remain.")


def cmd_gdrive_sync(args: argparse.Namespace) -> None:
    """Sync vault with Google Drive."""
    vault_path = Path(args.vault) if args.vault else None

    if not gdrive_sync(
        download=args.download,
        upload=args.upload,
        vault_path=vault_path,
    ):
        _die("Google Drive sync failed.")


def cmd_gdrive_logout(_args: argparse.Namespace) -> None:
    """Remove Google Drive credentials."""
    gdrive_logout()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="freeotp-vault",
        description="Encrypted OTP vault for FreeOTP JSON exports.",
    )
    p.add_argument(
        "--vault",
        metavar="PATH",
        default=None,
        help=f"Vault file path (default: {DEFAULT_VAULT_PATH})",
    )

    sub = p.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="Import a FreeOTP JSON export.")
    init_p.add_argument("json_file", help="Path to FreeOTP/FreeOTP+ JSON export.")

    list_p = sub.add_parser("list", help="List stored accounts.")
    list_p.add_argument(
        "--filter",
        "-f",
        metavar="TEXT",
        default=None,
        help="Filter by issuer or label (case-insensitive).",
    )

    token_p = sub.add_parser("token", help="Generate OTP tokens.")
    token_p.add_argument(
        "--filter",
        "-f",
        metavar="TEXT",
        default=None,
        help="Filter by issuer or label (case-insensitive).",
    )

    sub.add_parser("change-password", help="Re-encrypt vault with a new password.")

    remove_p = sub.add_parser("remove", help="Remove matching accounts from vault.")
    remove_p.add_argument(
        "--filter",
        "-f",
        metavar="TEXT",
        required=True,
        help="Filter accounts to remove.",
    )

    gdrive_p = sub.add_parser("gdrive-sync", help="Sync vault with Google Drive.")
    gdrive_p.add_argument(
        "--download",
        action="store_true",
        help="Download vault from Google Drive.",
    )
    gdrive_p.add_argument(
        "--upload",
        action="store_true",
        help="Upload vault to Google Drive.",
    )

    sub.add_parser("gdrive-logout", help="Remove Google Drive credentials.")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "init": cmd_init,
        "list": cmd_list,
        "token": cmd_token,
        "change-password": cmd_change_password,
        "remove": cmd_remove,
        "gdrive-sync": cmd_gdrive_sync,
        "gdrive-logout": cmd_gdrive_logout,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
