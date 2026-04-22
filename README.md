# freeotp-vault

Encrypted CLI vault for FreeOTP JSON exports with system keyring support.

[![PyPI](https://img.shields.io/pypi/v/freeotp-vault.svg)](https://pypi.org/project/freeotp-vault/)
[![Python](https://img.shields.io/pypi/pyversions/freeotp-vault.svg)](https://pypi.org/project/freeotp-vault/)
[![Coverage](https://codecov.io/gh/daedalus/freeotp-vault/branch/main/graph/badge.svg)](https://codecov.io/gh/daedalus/freeotp-vault)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Install

```bash
pip install freeotp-vault
```

## Usage

### Import a FreeOTP backup

```bash
freeotp-vault init path/to/freeotp-export.json
```

### List accounts

```bash
freeotp-vault list
freeotp-vault list --filter github
```

### Generate tokens

```bash
freeotp-vault token
freeotp-vault token --filter github
```

### Change password

```bash
freeotp-vault change-password
```

### Remove accounts

```bash
freeotp-vault remove --filter "old account"
```

### Google Drive Sync

Backup and sync your vault with Google Drive for cross-device access.

**Setup:**

1. Create OAuth credentials:
   - Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   - Create **OAuth client ID** → **Desktop app**
   - Download as `credentials.json`
   - Save to `~/.config/freeotp-vault/credentials.json`

2. Authenticate:

```bash
freeotp-vault gdrive-login
```

**Sync commands:**

```bash
# Upload vault to Google Drive
freeotp-vault gdrive-sync --upload

# Download vault from Google Drive
freeotp-vault gdrive-sync --download
```

## Python API

```python
from freeotp_vault import (
    encrypt_vault,
    decrypt_vault,
    parse_freeotp_json,
    generate_token,
    get_password_from_keyring,
    store_password_in_keyring,
)

# Parse a FreeOTP JSON export
tokens = parse_freeotp_json(json_string)

# Encrypt/decrypt vault data
blob = encrypt_vault(data, "password")
plaintext = decrypt_vault(blob, "password")

# Generate OTP code
code = generate_token(token_dict)
```

## Development

```bash
git clone https://github.com/daedalus/freeotp-vault.git
cd freeotp-vault
pip install -e ".[test]"

# With Google Drive support
pip install -e ".[gdrive]"
```

## License

MIT License - see LICENSE file.