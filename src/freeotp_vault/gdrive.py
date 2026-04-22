"""
Google Drive sync for vault backup and cross-device access.
Lazy-loaded: only imports google packages when gdrive commands are used.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import webbrowser
from pathlib import Path
from typing import TYPE_CHECKING, Any

SCOPES = ["https://www.googleapis.com/auth/drive.file"]
TOKEN_FILE = Path.home() / ".config" / "freeotp-vault" / "gdrive_token.json"
CLIENT_SECRETS = Path.home() / ".config" / "freeotp-vault" / "client_secrets.json"
VAULT_FILENAME = "freeotp-vault.enc"

if TYPE_CHECKING:
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import Resource


def _lazy_import_google_libs() -> tuple[Any, Any, Any, Any]:
    """Lazy import google libraries."""
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
        from googleapiclient.errors import HttpError
        from googleapiclient.http import MediaIoBaseUpload

        return InstalledAppFlow, build, HttpError, MediaIoBaseUpload
    except ImportError as e:
        raise ImportError(
            f"Google Drive sync requires additional packages: {e}\n"
            "Install with: pip install freeotp-vault[gdrive]"
        ) from None


def _get_client_config() -> dict[str, Any]:
    """Get OAuth client configuration."""
    if CLIENT_SECRETS.exists():
        return json.loads(CLIENT_SECRETS.read_text())
    client_id = os.environ.get("GDRIVE_CLIENT_ID", "")
    client_secret = os.environ.get("GDRIVE_CLIENT_SECRET", "")
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": ["http://localhost"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }


def _authenticate(verbose: bool = False, debug: bool = False) -> Any:
    """Authenticate with Google Drive using OAuth."""
    Flow, _, _, _ = _lazy_import_google_libs()

    client_config = _get_client_config()

    if verbose:
        print(f"[DEBUG] Client config: {client_config}")

    if not client_config.get("web", {}).get("client_id"):
        print("Error: Google Drive OAuth not configured.")
        print("Set GDRIVE_CLIENT_ID and GDRIVE_CLIENT_SECRET environment variables")
        print("or create ~/.config/freeotp-vault/client_secrets.json")
        sys.exit(1)

    flow = Flow.from_client_config(
        client_config,
        SCOPES,
        redirect_uris=["http://localhost"],
    )

    oauth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
    )

    print(f"[VERBOSE] OAuth URL: {oauth_url}")

    if verbose:
        print("[DEBUG] Detecting and opening default browser...")

    import platform
    if verbose:
        print(f"[DEBUG] Platform: {platform.system()}")

    browser_opened = webbrowser.open(oauth_url)

    if verbose:
        print(f"[DEBUG] Browser opened via webbrowser: {browser_opened}")

    if not browser_opened:
        if verbose:
            print("[DEBUG] Trying alternative browser methods...")

        for browser in ["firefox", "chrome", "chromium", "brave", "edge"]:
            try:
                webbrowser.get(browser).open(oauth_url)
                if verbose:
                    print(f"[DEBUG] Opened with {browser}")
                break
            except webbrowser.Error:
                continue

    print(f"Opening browser for OAuth authorization...")
    print(f"If browser doesn't open, visit: {oauth_url}")

    try:
        flow.run_local_server(
            port=8080,
            open_browser=False,
            prompt="consent",
        )
    except Exception as e:
        if verbose or debug:
            print(f"[DEBUG] OAuth error: {e}")
        raise

    token = flow.credentials
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(token.to_json())

    if verbose:
        print("[DEBUG] Credentials saved")

    return token


class _GoogleAuth:
    """Lazy google auth handler."""

    @staticmethod
    def get_credentials() -> Any:
        """Load stored credentials or re-authenticate."""
        if not TOKEN_FILE.exists():
            return _authenticate()

        from google.auth.exceptions import RefreshError
        import google.auth.transport.requests
        from google.oauth2.credentials import Credentials

        try:
            creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
            if creds.expired or creds.refresh_token is None:
                return _authenticate()

            try:
                creds.refresh(google.auth.transport.requests.Request())
                TOKEN_FILE.write_text(creds.to_json())
            except RefreshError:
                return _authenticate()

            return creds
        except Exception:
            return _authenticate()

    @staticmethod
    def get_drive_service() -> "Resource":
        """Get Google Drive service."""
        _, build, _, _ = _lazy_import_google_libs()
        creds = _GoogleAuth.get_credentials()
        return build("drive", "v3", credentials=creds)


def _find_vault_file(service: "Resource") -> dict[str, str] | None:
    """Find existing vault file in Google Drive."""
    _, _, HttpError, _ = _lazy_import_google_libs()

    try:
        results = (
            service.files()
            .get(
                q=f"name='{VAULT_FILENAME}' and trashed=false",
                pageSize=10,
                fields="files(id, name, modifiedTime)",
            )
            .execute()
        )
        files = results.get("files", [])
        return files[0] if files else None
    except HttpError:
        return None


def gdrive_sync(download: bool = False, upload: bool = False, vault_path: Path | None = None) -> bool:
    """Sync vault with Google Drive.

    Args:
        download: If True, download vault from Drive instead of uploading.
        upload: If True, upload vault to Drive.
        vault_path: Optional custom vault path.

    Returns:
        True on success.
    """
    from .vault import DEFAULT_VAULT_PATH, vault_exists

    vault = vault_path or DEFAULT_VAULT_PATH
    if not vault_exists(vault):
        print(f"Vault not found at {vault}. Run `init` first.")
        return False

    try:
        service = _GoogleAuth.get_drive_service()
    except SystemExit:
        return False

    try:
        remote_file = _find_vault_file(service)

        if download or (not upload and not remote_file):
            if not remote_file:
                print("No vault found in Google Drive. Use --upload to create one.")
                return False

            print("Downloading vault from Google Drive...")
            _, _, _, MediaIoBaseUpload = _lazy_import_google_libs()

            request = service.files().get_media(fileId=remote_file["id"])
            vault_data = request.execute()

            vault_tmp = vault.with_suffix(".tmp")
            vault_tmp.write_bytes(vault_data)
            vault_tmp.replace(vault)

            print(f"Vault downloaded to {vault}")
            return True

        if upload:
            print("Uploading vault to Google Drive...")
            _, _, _, MediaIoBaseUpload = _lazy_import_google_libs()

            with open(vault, "rb") as f:
                media = MediaIoBaseUpload(f, mimetype="application/octet-stream")

            if remote_file:
                service.files().update(
                    fileId=remote_file["id"],
                    media_body=media,
                ).execute()
            else:
                metadata = {"name": VAULT_FILENAME, "parents": ["root"]}
                service.files().create(
                    body=metadata,
                    media_body=media,
                ).execute()

            print("Vault uploaded to Google Drive")
            return True

        print("Use --download or --upload to specify sync direction")
        return False

    except Exception as e:
        print(f"Google Drive error: {e}")
        return False


def gdrive_logout() -> None:
    """Remove stored Google Drive credentials."""
    if TOKEN_FILE.exists():
        TOKEN_FILE.unlink()
        print("Logged out of Google Drive.")