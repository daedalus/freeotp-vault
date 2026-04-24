"""
freeotp-vault — command-line OTP vault for FreeOTP JSON exports.

Usage:
  freeotp-vault init <json_file>          Import + encrypt a FreeOTP export
  freeotp-vault import-vault <file> [dest] Import an encrypted vault
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
    keyring_available,
    store_password_in_keyring,
)
from .otp import generate_token, seconds_remaining
from .parser import Token, parse_freeotp_json
from .vault import (
    DEFAULT_VAULT_PATH,
    filter_tokens,
    load_tokens,
    save_tokens,
    save_vault,
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

    if not keyring_available():
        print("[warn] System keyring unavailable. Password will not be saved.")

    for attempt in range(3):
        password = getpass.getpass(f"Vault password (attempt {attempt + 1}/3): ")
        try:
            tokens = load_tokens(password, vault_path)
            if keyring_available():
                try:
                    save = (
                        input("Save password to system keyring? [y/N] ").strip().lower()
                    )
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


def cmd_import_vault(args: argparse.Namespace) -> None:
    from .vault import load_vault, save_vault, vault_exists

    source_path = Path(args.vault_file)
    if not source_path.exists():
        _die(f"File not found: {source_path}")

    dest_path = Path(args.dest) if args.dest else DEFAULT_VAULT_PATH
    if vault_exists(dest_path) and not args.force:
        try:
            confirm = (
                input(f"Vault already exists at {dest_path}. Merge? [y/N] ")
                .strip()
                .lower()
            )
        except EOFError:
            confirm = "n"
        if confirm != "y":
            print("Aborted.")
            return

    source_password = getpass.getpass("Source vault password: ")
    try:
        source_vault = load_vault(source_password, source_path)
    except ValueError as exc:
        _die(f"Could not unlock source vault: {exc}")

    source_tokens = source_vault.get("tokens", [])
    source_gdrive_auth = source_vault.get("gdrive_auth")
    print(f"Loaded {len(source_tokens)} token(s) from source vault.")

    dest_tokens: list[Token] = []
    dest_gdrive_auth = None

    if vault_exists(dest_path):
        dest_password = get_password_from_keyring(str(dest_path.resolve()))
        if not dest_password:
            dest_password = getpass.getpass("Destination vault password: ")
        try:
            dest_vault = load_vault(dest_password, dest_path)
        except ValueError as exc:
            _die(f"Could not unlock destination vault: {exc}")
        dest_tokens = dest_vault.get("tokens", [])
        dest_gdrive_auth = dest_vault.get("gdrive_auth")
        print(f"Loaded {len(dest_tokens)} token(s) from destination vault.")

    merged_tokens = dest_tokens + source_tokens

    merged_gdrive_auth = source_gdrive_auth or dest_gdrive_auth

    print(f"Total {len(merged_tokens)} token(s) after merge.")

    new_password = _ask_new_password()
    save_vault(merged_tokens, new_password, dest_path, merged_gdrive_auth)
    print(f"Vault saved to: {dest_path}")

    abs_path = str(dest_path.resolve())
    try:
        save_kr = input("Save password to system keyring? [y/N] ").strip().lower()
    except EOFError:
        save_kr = "n"
    if save_kr == "y":
        if store_password_in_keyring(abs_path, new_password):
            print("  Password stored in keyring.")
        else:
            print("  Keyring unavailable; password NOT stored.")


def cmd_init(args: argparse.Namespace) -> None:
    from .parser import extract_gdrive_auth

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

    gdrive_auth = extract_gdrive_auth(raw)

    print(f"Found {len(tokens)} token(s). Creating encrypted vault...")
    password = _ask_new_password()
    save_vault(tokens, password, vault_path, gdrive_auth)
    print(f"Vault created: {vault_path}")

    if gdrive_auth:
        print("  Google Drive auth data saved to vault.")

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
    from .keyring_store import get_password_from_keyring

    vault_path = Path(args.vault) if args.vault else DEFAULT_VAULT_PATH
    vp = vault_path.resolve()

    vault_password: str | None = None
    if vault_exists(vault_path):
        try:
            vault_password = get_password_from_keyring(str(vp))
        except Exception:
            vault_password = None

    if not gdrive_sync(
        download=args.download,
        upload=args.upload,
        vault_path=vault_path,
        vault_password=vault_password,
    ):
        _die("Google Drive sync failed.")


def cmd_gdrive_login(args: argparse.Namespace) -> None:
    """Authenticate with Google Drive."""
    from .gdrive import _authenticate as gdrive_auth
    from .vault import DEFAULT_VAULT_PATH

    vault_path = Path(args.vault) if args.vault else None
    vp = vault_path or DEFAULT_VAULT_PATH

    vault_password: str | None = None
    if vault_exists(vp):
        try:
            from .keyring_store import get_password_from_keyring

            vault_password = get_password_from_keyring(str(vp.resolve()))
        except Exception:
            vault_password = None

        if vault_password is None:
            try:
                vault_password = getpass.getpass("Vault password (for gdrive auth): ")
            except EOFError:
                vault_password = None

    print("Opening browser for Google Drive authentication...")
    gdrive_auth(
        verbose=args.verbose,
        vault_password=vault_password,
        vault_path=vault_path,
    )
    print("Successfully authenticated with Google Drive.")


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
    p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output.",
    )
    p.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output.",
    )

    sub = p.add_subparsers(dest="command", required=True)

    init_p = sub.add_parser("init", help="Import a FreeOTP JSON export.")
    init_p.add_argument("json_file", help="Path to FreeOTP/FreeOTP+ JSON export.")

    import_vault_p = sub.add_parser(
        "import-vault", help="Import an encrypted vault to a new location."
    )
    import_vault_p.add_argument("vault_file", help="Path to the encrypted vault.")
    import_vault_p.add_argument(
        "dest",
        nargs="?",
        default=None,
        help=f"Destination path (default: {DEFAULT_VAULT_PATH})",
    )
    import_vault_p.add_argument(
        "-f",
        "--force",
        action="store_true",
        help="Overwrite destination without prompting.",
    )

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

    sub.add_parser("gdrive-login", help="Authenticate with Google Drive.")

    sub.add_parser("gdrive-logout", help="Remove Google Drive credentials.")

    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "init": cmd_init,
        "import-vault": cmd_import_vault,
        "list": cmd_list,
        "token": cmd_token,
        "change-password": cmd_change_password,
        "remove": cmd_remove,
        "gdrive-sync": cmd_gdrive_sync,
        "gdrive-login": cmd_gdrive_login,
        "gdrive-logout": cmd_gdrive_logout,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
