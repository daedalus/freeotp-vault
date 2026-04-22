# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Added
- Store gdrive auth data in vault during `init` (extracts from JSON if present)
- `_get_client_config` checks vault first, then env vars, then config files
- `gdrive_token.json` included in auth data priority chain
- `_authenticate` uses refresh_token from vault to skip browser OAuth
- Vault auth functions plumbed through `gdrive_sync` and `gdrive_login`

### Fixed
- Removed unused imports throughout codebase

[v0.1.0.1]: https://github.com/daedalus/freeotp-vault/releases/tag/v0.1.0.1