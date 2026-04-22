# AGENTS.md — freeotp-vault

## Overview

Encrypted CLI vault for FreeOTP JSON exports with system keyring support. Imports FreeOTP/FreeOTP+
JSON exports, encrypts vault with AES-256-GCM, and generates TOTP/HOTP tokens.

## Commands

| Command | Description |
|---------|------------|
| `pytest` | Run test suite |
| `ruff format` | Format code |
| `ruff check` | Lint code |
| `mypy src/` | Type check |

## Development

```bash
# Setup
pip install -e ".[test]"

# Test
pytest

# Lint
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/
```

## Testing

Uses pytest with fixtures from `tests/conftest.py`. Pre-existing fixture bug in
`freeotp_json_bytes` (invalid base32 padding).

## Code Style

- Format: ruff
- Lint: ruff + mypy
- Docstrings: Google style

## Release

```bash
# Bump version
bumpversion patch  # or minor/major
git tag v<version>
git push && git push --tags
```