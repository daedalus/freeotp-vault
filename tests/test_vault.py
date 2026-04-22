"""Tests for freeotp_vault.vault."""


import pytest

from freeotp_vault.vault import filter_tokens, load_tokens, save_tokens, vault_exists


class TestVaultRoundtrip:
    def test_save_and_load(self, tmp_path, token_list):
        vp = tmp_path / "vault.enc"
        save_tokens(token_list, "secret", vp)
        loaded = load_tokens("secret", vp)
        assert loaded == token_list

    def test_vault_permissions(self, tmp_path, token_list):
        vp = tmp_path / "vault.enc"
        save_tokens(token_list, "pw", vp)

        mode = vp.stat().st_mode & 0o777
        assert mode == 0o600

    def test_wrong_password_raises(self, tmp_path, token_list):
        vp = tmp_path / "vault.enc"
        save_tokens(token_list, "correct", vp)
        with pytest.raises(ValueError, match="Wrong password"):
            load_tokens("wrong", vp)

    def test_missing_vault_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_tokens("pw", tmp_path / "nonexistent.enc")

    def test_vault_exists_true(self, tmp_path, token_list):
        vp = tmp_path / "vault.enc"
        save_tokens(token_list, "pw", vp)
        assert vault_exists(vp) is True

    def test_vault_exists_false(self, tmp_path):
        assert vault_exists(tmp_path / "nope.enc") is False

    def test_creates_parent_dirs(self, tmp_path, token_list):
        vp = tmp_path / "a" / "b" / "vault.enc"
        save_tokens(token_list, "pw", vp)
        assert vp.exists()

    def test_overwrite_vault(self, tmp_path, token_list, totp_token):
        vp = tmp_path / "vault.enc"
        save_tokens(token_list, "pw1", vp)
        save_tokens([totp_token], "pw2", vp)
        loaded = load_tokens("pw2", vp)
        assert len(loaded) == 1

    def test_empty_token_list(self, tmp_path):
        vp = tmp_path / "vault.enc"
        save_tokens([], "pw", vp)
        loaded = load_tokens("pw", vp)
        assert loaded == []


class TestFilterTokens:
    def test_no_filter_returns_all(self, token_list):
        assert filter_tokens(token_list, None) == token_list

    def test_empty_string_returns_all(self, token_list):
        assert filter_tokens(token_list, "") == token_list

    def test_filter_by_issuer(self, token_list):
        result = filter_tokens(token_list, "github")
        assert len(result) == 1
        assert result[0]["issuer"] == "GitHub"

    def test_filter_by_label(self, token_list):
        result = filter_tokens(token_list, "bob")
        assert len(result) == 1
        assert result[0]["label"] == "bob@acme.com"

    def test_filter_case_insensitive(self, token_list):
        assert filter_tokens(token_list, "GITHUB") == filter_tokens(
            token_list, "github"
        )

    def test_filter_no_match_returns_empty(self, token_list):
        assert filter_tokens(token_list, "zzznomatch") == []

    def test_filter_partial_match(self, token_list):
        result = filter_tokens(token_list, "example")
        # alice@example.com matches
        assert any(t["label"] == "alice@example.com" for t in result)
