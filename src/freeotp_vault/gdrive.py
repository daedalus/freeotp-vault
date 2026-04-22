"""
Google Drive sync for vault backup and cross-device access.
Lazy-loaded: only imports google packages when gdrive commands are used.
"""

from __future__ import annotations

import json
import os
import json
import random
import platform
import sys
import webbrowser
import contextlib
import logging
import io
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

SCOPES = ["https://www.googleapis.com/auth/drive.file"]
TOKEN_FILE = Path.home() / ".config" / "freeotp-vault" / "gdrive_token.json"
CLIENT_SECRETS = Path.home() / ".config" / "freeotp-vault"
CLIENT_SECRETS_FILE = CLIENT_SECRETS / "client_secrets.json"
CREDENTIALS_FILE = CLIENT_SECRETS / "credentials.json"
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


def _get_client_config(verbose: bool = False) -> dict[str, Any]:
    """Get OAuth client configuration."""
    client_id = os.environ.get("GDRIVE_CLIENT_ID", "")
    client_secret = os.environ.get("GDRIVE_CLIENT_SECRET", "")

    if verbose:
        print(f"[DEBUG] GDRIVE_CLIENT_ID env: '{client_id}'")
        print(f"[DEBUG] GDRIVE_CLIENT_SECRET env: '{client_secret[:4]}...' " if client_secret else "[DEBUG] GDRIVE_CLIENT_SECRET env: ''")

    if not client_id and CLIENT_SECRETS_FILE.exists():
        data = json.loads(CLIENT_SECRETS_FILE.read_text())
        if verbose:
            print(f"[DEBUG] Loaded from client_secrets.json")
        web_config = data.get("web", data.get("installed", {}))
        client_id = web_config.get("client_id", "")
        client_secret = web_config.get("client_secret", "")
    elif not client_id and CREDENTIALS_FILE.exists():
        data = json.loads(CREDENTIALS_FILE.read_text())
        if verbose:
            print(f"[DEBUG] Loaded from credentials.json")
        web_config = data.get("web", data.get("installed", {}))
        client_id = web_config.get("client_id", "")
        client_secret = web_config.get("client_secret", "")

    if not client_id:
        if verbose:
            print("[DEBUG] No client_id found")
        return {
            "web": {
                "client_id": "",
                "client_secret": "",
                "redirect_uris": [],
                "auth_uri": "",
                "token_uri": "",
            }
        }

    if verbose:
        print("[DEBUG] Using env-based config")

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
    print("Starting Google Drive authentication...", flush=True)
    Flow, _, _, _ = _lazy_import_google_libs()

    client_config = _get_client_config(verbose=verbose)

    if not client_config.get("web", {}).get("client_id"):
        print("Error: Google Drive OAuth not configured.")
        print("Set GDRIVE_CLIENT_ID and GDRIVE_CLIENT_SECRET environment variables")
        print("or create ~/.config/freeotp-vault/credentials.json")
        sys.exit(1)

    flow = Flow.from_client_config(
        client_config,
        SCOPES,
    )
    port = random.randint(10000, 60000)
    flow.redirect_uri = f"http://localhost:{port}"

    print(f"Opening browser for OAuth authorization...")

    try:
        import warnings
        import logging
        import io
        import sys
        import contextlib

        logging.getLogger("google_auth_oauthlib").setLevel(logging.ERROR)
        logging.getLogger("google_auth_oauthlib.flow").setLevel(logging.ERROR)
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = io.StringIO()
            sys.stderr = io.StringIO()
            try:
                flow.run_local_server(
                    port=port,
                    open_browser=True,
                    prompt="consent",
                )
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
    except Exception as e:
        print(f"OAuth error: {e}")
        raise

    token = flow.credentials
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(token.to_json())

    print("Successfully authenticated with Google Drive!")
    print(f"Credentials saved to: {TOKEN_FILE}")

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
    def _get_http_session() -> Any:
        """Get authenticated requests session with proxy support."""
        import requests
        
        creds = _GoogleAuth.get_credentials()
        access_token = creds.token
        
        session = requests.Session()
        session.headers.update({"Authorization": f"Bearer {access_token}"})
        
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy") or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        
        if http_proxy:
            session.proxies = {"http": http_proxy, "https": https_proxy or http_proxy}
        
        return session


def _find_vault_file(service: "Resource") -> dict[str, str] | None:
    """Find existing vault file in Google Drive."""
    _, _, HttpError, _ = _lazy_import_google_libs()

    try:
        results = (
            service.files()
            .list(
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
    import requests
    from .vault import DEFAULT_VAULT_PATH, vault_exists

    vault = vault_path or DEFAULT_VAULT_PATH
    if not vault_exists(vault):
        print(f"Vault not found at {vault}. Run `init` first.")
        return False

    try:
        session = _GoogleAuth._get_http_session()
    except SystemExit:
        return False

    try:
        upload_url = "https://www.googleapis.com/upload/drive/v3/files"
        query_url = "https://www.googleapis.com/drive/v3/files"
        
        headers = {"Authorization": f"Bearer {session.headers.get('Authorization', '').replace('Bearer ', '')}"}
        
        proxy = os.environ.get("HTTP_PROXY") or os.environ.get("https_proxy") or ""
        proxies = {"http": proxy, "https": proxy} if proxy else None
        
        if upload:
            files_in_drive = session.get(query_url, params={"q": f"name='{VAULT_FILENAME}' and trashed=false"}, proxies=proxies).json()
            existing = files_in_drive.get("files", [])
            
            with open(vault, "rb") as f:
                vault_data = f.read()
            
            if existing:
                file_id = existing[0]["id"]
                print(f"Updating existing vault in Google Drive...")
                session.patch(
                    f"https://www.googleapis.com/drive/v3/files/{file_id}",
                    headers=headers,
                    files={"data": ("metadata", '{"mimeType": "application/octet-stream"}', "application/json")},
                    data=vault_data,
                    proxies=proxies,
                )
            else:
                print(f"Uploading vault to Google Drive...")
                metadata = {"name": VAULT_FILENAME}
                multipart = [
                    ("metadata", (None, json.dumps(metadata), "application/json")),
                    ("file", (VAULT_FILENAME, vault_data, "application/octet-stream")),
                ]
                session.post(
                    "https://www.googleapis.com/upload/drive/v3/files",
                    files=multipart,
                    proxies=proxies,
                )
            
            print("Vault uploaded to Google Drive")
            return True

        if download:
            files_in_drive = session.get(query_url, params={"q": f"name='{VAULT_FILENAME}' and trashed=false"}, proxies=proxies).json()
            existing = files_in_drive.get("files", [])
            
            if not existing:
                print("No vault found in Google Drive. Use --upload to create one.")
                return False
            
            file_id = existing[0]["id"]
            print("Downloading vault from Google Drive...")
            
            content = session.get(
                f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media",
                proxies=proxies,
            ).content
            
            vault_tmp = vault.with_suffix(".tmp")
            vault_tmp.write_bytes(content)
            vault_tmp.replace(vault)
            
            print(f"Vault downloaded to {vault}")
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