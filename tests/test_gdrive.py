"""Tests for Google Drive sync."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_credentials_file(tmp_path, monkeypatch):
    """Create a mock credentials file."""
    creds_dir = tmp_path / ".config" / "freeotp-vault"
    creds_dir.mkdir(parents=True)
    creds_file = creds_dir / "credentials.json"
    
    creds_data = {
        "installed": {
            "client_id": "test-client-id.apps.googleusercontent.com",
            "client_secret": "test-secret",
            "redirect_uris": ["http://localhost"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    }
    creds_file.write_text(json.dumps(creds_data))
    monkeypatch.setenv("HOME", str(tmp_path))
    return creds_file


@pytest.fixture
def mock_token_file(tmp_path, monkeypatch):
    """Create a mock token file."""
    token_dir = tmp_path / ".config" / "freeotp-vault"
    token_dir.mkdir(parents=True)
    token_file = token_dir / "gdrive_token.json"
    
    token_data = {
        "token": "test-access-token",
        "refresh_token": "test-refresh-token",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "test-client-id",
        "client_secret": "test-secret",
        "scopes": ["https://www.googleapis.com/auth/drive.file"],
    }
    token_file.write_text(json.dumps(token_data))
    monkeypatch.setenv("HOME", str(tmp_path))
    return token_file


class TestClientConfig:
    """Tests for OAuth client configuration."""

    def test_loads_from_credentials_json(self, mock_credentials_file):
        """Loads client config from credentials.json."""
        from freeotp_vault.gdrive import _get_client_config
        
        config = _get_client_config(verbose=False)
        web = config.get("web", {})
        
        assert web.get("client_id") == "test-client-id.apps.googleusercontent.com"
        assert web.get("client_secret") == "test-secret"

    def test_loads_from_env_vars(self, monkeypatch):
        """Loads client config from environment variables."""
        monkeypatch.setenv("GDRIVE_CLIENT_ID", "env-client-id")
        monkeypatch.setenv("GDRIVE_CLIENT_SECRET", "env-secret")
        
        from freeotp_vault.gdrive import _get_client_config
        
        config = _get_client_config(verbose=False)
        web = config.get("web", {})
        
        assert web.get("client_id") == "env-client-id"
        assert web.get("client_secret") == "env-secret"

    def test_env_overrides_file(self, mock_credentials_file, monkeypatch):
        """Environment variables take precedence over file."""
        monkeypatch.setenv("GDRIVE_CLIENT_ID", "env-client-id")
        monkeypatch.setenv("GDRIVE_CLIENT_SECRET", "env-secret")
        
        from freeotp_vault.gdrive import _get_client_config
        
        config = _get_client_config(verbose=False)
        web = config.get("web", {})
        
        assert web.get("client_id") == "env-client-id"

    def test_returns_empty_config_when_unconfigured(self, tmp_path, monkeypatch):
        """Returns empty config when no credentials found."""
        monkeypatch.setenv("HOME", str(tmp_path))
        
        from freeotp_vault.gdrive import _get_client_config
        
        config = _get_client_config(verbose=False)
        
        assert config.get("web", {}).get("client_id") == ""


class TestHttpSession:
    """Tests for authenticated HTTP session."""

    def test_session_has_bearer_token(self, mock_token_file):
        """Session includes Bearer token."""
        from freeotp_vault.gdrive import _GoogleAuth
        
        session = _GoogleAuth._get_http_session()
        
        auth_header = session.headers.get("Authorization", "")
        assert auth_header == "Bearer test-access-token"

    def test_session_uses_proxy(self, mock_token_file, monkeypatch):
        """Session uses proxy from environment."""
        monkeypatch.setenv("HTTP_PROXY", "http://proxy.example.com:8080")
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example.com:8080")
        
        from freeotp_vault.gdrive import _GoogleAuth
        
        session = _GoogleAuth._get_http_session()
        
        assert session.proxies.get("http") == "http://proxy.example.com:8080"
        assert session.proxies.get("https") == "http://proxy.example.com:8080"

    def test_session_no_proxy_when_not_set(self, mock_token_file, monkeypatch):
        """Session has no proxy when environment not set."""
        monkeypatch.delenv("HTTP_PROXY", raising=False)
        monkeypatch.delenv("HTTPS_PROXY", raising=False)
        monkeypatch.delenv("http_proxy", raising=False)
        monkeypatch.delenv("https_proxy", raising=False)
        
        from freeotp_vault.gdrive import _GoogleAuth
        
        session = _GoogleAuth._get_http_session()
        
        assert session.proxies is None or session.proxies == {}


class TestGdriveSync:
    """Tests for vault sync."""

    @patch("freeotp_vault.gdrive._GoogleAuth._get_http_session")
    def test_upload_creates_vault_file(self, mock_session, mock_token_file, tmp_path):
        """Uploads vault to Google Drive."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"files": []}
        
        mock_sess = MagicMock()
        mock_sess.get.return_value = mock_resp
        mock_sess.post.return_value = MagicMock()
        mock_sess.headers = {"Authorization": "Bearer token"}
        mock_session.return_value = mock_sess
        
        from freeotp_vault.gdrive import gdrive_sync
        from freeotp_vault.vault import DEFAULT_VAULT_PATH
        
        vault = tmp_path / "vault.enc"
        vault.write_bytes(b"encrypted vault data")
        
        result = gdrive_sync(upload=True, vault_path=vault)
        
        assert result is True
        mock_sess.post.assert_called_once()

    @patch("freeotp_vault.gdrive._GoogleAuth._get_http_session")
    def test_download_gets_vault_file(self, mock_session, mock_token_file, tmp_path):
        """Downloads vault from Google Drive."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "files": [{"id": "abc123", "name": "freeotp-vault.enc"}]
        }
        
        mock_sess = MagicMock()
        mock_sess.get.return_value = mock_resp
        mock_sess.headers = {"Authorization": "Bearer token"}
        mock_session.return_value = mock_sess
        
        from freeotp_vault.gdrive import gdrive_sync
        from freeotp_vault.vault import DEFAULT_VAULT_PATH
        
        vault = tmp_path / "vault.enc"
        
        result = gdrive_sync(download=True, vault_path=vault)
        
        assert result is True

    @patch("freeotp_vault.gdrive._GoogleAuth._get_http_session")
    def test_update_existing_vault(self, mock_session, mock_token_file, tmp_path):
        """Updates existing vault file on Drive."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "files": [{"id": "abc123", "name": "freeotp-vault.enc"}]
        }
        
        mock_sess = MagicMock()
        mock_sess.get.return_value = mock_resp
        mock_sess.patch.return_value = MagicMock()
        mock_sess.headers = {"Authorization": "Bearer token"}
        mock_session.return_value = mock_sess
        
        from freeotp_vault.gdrive import gdrive_sync
        
        vault = tmp_path / "vault.enc"
        vault.write_bytes(b"encrypted vault data")
        
        result = gdrive_sync(upload=True, vault_path=vault)
        
        assert result is True
        mock_sess.patch.assert_called_once()

    def test_requires_vault_file(self, tmp_path):
        """Fails when vault doesn't exist."""
        from freeotp_vault.gdrive import gdrive_sync
        
        vault = tmp_path / "nonexistent.enc"
        
        result = gdrive_sync(upload=True, vault_path=vault)
        
        assert result is False