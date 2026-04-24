"""Tests for Google Drive sync."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_creds():
    """Mock Google credentials."""
    creds = MagicMock()
    creds.token = "test-access-token"
    creds.refresh_token = "test-refresh"
    creds.token_uri = "https://oauth2.googleapis.com/token"
    creds.client_id = "test-client"
    creds.client_secret = "test-secret"
    creds.scopes = []
    return creds


class TestClientConfig:
    """Tests for OAuth client configuration."""

    @patch("freeotp_vault.gdrive._get_client_config")
    def test_loads_from_credentials_json(self, mock_config):
        """Loads client config from credentials.json."""
        mock_config.return_value = {
            "web": {
                "client_id": "test-client-id.apps.googleusercontent.com",
                "client_secret": "test-secret",
            }
        }

        from freeotp_vault.gdrive import _get_client_config

        config = _get_client_config(verbose=False)
        web = config.get("web", {})

        assert web.get("client_id") == "test-client-id.apps.googleusercontent.com"
        assert web.get("client_secret") == "test-secret"

    @patch("freeotp_vault.gdrive._get_client_config")
    def test_loads_from_env_vars(self, mock_config):
        """Loads client config from environment variables."""
        mock_config.return_value = {
            "web": {
                "client_id": "env-client-id",
                "client_secret": "env-secret",
            }
        }

        from freeotp_vault.gdrive import _get_client_config

        config = _get_client_config(verbose=False)
        web = config.get("web", {})

        assert web.get("client_id") == "env-client-id"
        assert web.get("client_secret") == "env-secret"

    @patch("freeotp_vault.gdrive._get_client_config")
    def test_env_overrides_file(self, mock_config):
        """Environment variables take precedence over file."""
        mock_config.return_value = {
            "web": {
                "client_id": "env-client-id",
                "client_secret": "env-secret",
            }
        }

        from freeotp_vault.gdrive import _get_client_config

        config = _get_client_config(verbose=False)
        web = config.get("web", {})

        assert web.get("client_id") == "env-client-id"

    @patch("freeotp_vault.gdrive._get_client_config")
    def test_returns_empty_config_when_unconfigured(self, mock_config):
        """Returns empty config when no credentials found."""
        mock_config.return_value = {
            "web": {
                "client_id": "",
                "client_secret": "",
            }
        }

        from freeotp_vault.gdrive import _get_client_config

        config = _get_client_config(verbose=False)

        assert config.get("web", {}).get("client_id") == ""


class TestHttpSession:
    """Tests for authenticated HTTP session."""

    @patch("freeotp_vault.gdrive._GoogleAuth.get_credentials")
    def test_session_has_bearer_token(self, mock_get_creds, mock_creds):
        """Session includes Bearer token."""
        mock_get_creds.return_value = mock_creds

        from freeotp_vault.gdrive import _GoogleAuth

        session = _GoogleAuth._get_http_session()

        auth_header = session.headers.get("Authorization", "")
        assert auth_header == "Bearer test-access-token"

    @patch("freeotp_vault.gdrive._GoogleAuth.get_credentials")
    @patch.dict(
        "os.environ",
        {
            "HTTP_PROXY": "http://proxy.example.com:8080",
            "HTTPS_PROXY": "http://proxy.example.com:8080",
        },
    )
    def test_session_uses_proxy(self, mock_get_creds, mock_creds):
        """Session uses proxy from environment."""
        mock_get_creds.return_value = mock_creds

        from freeotp_vault.gdrive import _GoogleAuth

        session = _GoogleAuth._get_http_session()

        assert session.proxies.get("http") == "http://proxy.example.com:8080"


class TestGdriveSync:
    """Tests for vault sync."""

    @patch("freeotp_vault.gdrive._GoogleAuth._get_http_session")
    @patch("freeotp_vault.gdrive._GoogleAuth.get_credentials")
    def test_upload_creates_vault_file(
        self, mock_get_creds, mock_session, tmp_path, mock_creds
    ):
        """Uploads vault to Google Drive."""
        mock_get_creds.return_value = mock_creds

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"files": []}

        mock_sess = MagicMock()
        mock_sess.get.return_value = mock_resp
        mock_sess.post.return_value = MagicMock()
        mock_sess.headers = {"Authorization": "Bearer token"}
        mock_session.return_value = mock_sess

        from freeotp_vault.gdrive import gdrive_sync

        vault = tmp_path / "vault.enc"
        vault.write_bytes(b"encrypted vault data")

        result = gdrive_sync(upload=True, vault_path=vault)

        assert result is True
        mock_sess.post.assert_called_once()

    @patch("freeotp_vault.gdrive._GoogleAuth._get_http_session")
    @patch("freeotp_vault.gdrive._GoogleAuth.get_credentials")
    def test_download_gets_vault_file(
        self, mock_get_creds, mock_session, tmp_path, mock_creds
    ):
        """Downloads vault from Google Drive."""
        mock_get_creds.return_value = mock_creds

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "files": [{"id": "abc123", "name": "freeotp-vault.enc"}]
        }
        mock_download = MagicMock()
        mock_download.content = b"encrypted vault data"

        mock_sess = MagicMock()
        mock_sess.get.side_effect = [mock_resp, mock_download]
        mock_sess.headers = {"Authorization": "Bearer token"}
        mock_session.return_value = mock_sess

        from freeotp_vault.gdrive import gdrive_sync

        vault = tmp_path / "vault.enc"
        vault.touch()

        result = gdrive_sync(download=True, vault_path=vault)

        assert result is True

    @patch("freeotp_vault.gdrive._GoogleAuth._get_http_session")
    @patch("freeotp_vault.gdrive._GoogleAuth.get_credentials")
    def test_update_existing_vault(
        self, mock_get_creds, mock_session, tmp_path, mock_creds
    ):
        """Updates existing vault file on Drive."""
        mock_get_creds.return_value = mock_creds

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

    @patch("freeotp_vault.gdrive._GoogleAuth.get_credentials")
    def test_requires_vault_file(self, mock_get_creds, tmp_path):
        """Fails when vault doesn't exist."""
        from freeotp_vault.gdrive import gdrive_sync

        vault = tmp_path / "nonexistent.enc"

        result = gdrive_sync(upload=True, vault_path=vault)

        assert result is False

    @patch("freeotp_vault.gdrive._GoogleAuth._get_http_session")
    @patch("freeotp_vault.gdrive._GoogleAuth.get_credentials")
    def test_download_no_vault_in_drive(
        self, mock_get_creds, mock_session, tmp_path, mock_creds
    ):
        """Fails when no vault in Drive."""
        mock_get_creds.return_value = mock_creds

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"files": []}

        mock_sess = MagicMock()
        mock_sess.get.return_value = mock_resp
        mock_sess.headers = {"Authorization": "Bearer token"}
        mock_session.return_value = mock_sess

        from freeotp_vault.gdrive import gdrive_sync

        vault = tmp_path / "vault.enc"

        result = gdrive_sync(download=True, vault_path=vault)

        assert result is False
