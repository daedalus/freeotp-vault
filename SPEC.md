# SPEC.md — freeotp-vault

## Purpose
CLI tool that imports a FreeOTP/FreeOTP+ JSON export, encrypts the vault with
AES-256-GCM (password-derived key via scrypt), stores the unlock password in the
OS keyring, and generates TOTP/HOTP tokens on demand. Supports optional
Google Drive sync for backup and cross-device access.

## Scope

**In scope:**
- `init <json_file>`   — import FreeOTP JSON, ask password, store encrypted vault
- `token [filter]`     — generate current OTP tokens (filter by issuer/label)
- `list`               — list stored accounts (no secrets shown)
- `change-password`    — re-encrypt vault with a new password
- `remove <filter>`    — delete matching accounts from the vault
- `gdrive-sync`        — sync vault to/from Google Drive

**Not in scope:**
- GUI / TUI
- QR-code scanning
- Writing back to FreeOTP format
- Windows DPAPI or macOS Keychain workarounds beyond `keyring` stdlib
- Other cloud providers (only Google Drive supported)

## Public API / Interface

### CLI entry point: `freeotp-vault`

```
freeotp-vault init <json_file>
freeotp-vault list [--filter TEXT]
freeotp-vault token [--filter TEXT] [--once]
freeotp-vault change-password
freeotp-vault remove --filter TEXT
freeotp-vault gdrive-sync [--download | --upload]
```

### Python API (importable)

```python
def encrypt_vault(data: bytes, password: str) -> bytes:
    """AES-256-GCM encrypt data with scrypt-derived key. Returns blob."""

def decrypt_vault(blob: bytes, password: str) -> bytes:
    """Decrypt AES-256-GCM blob. Raises ValueError on bad password/corruption."""

def parse_freeotp_json(raw: str) -> list[dict]:
    """Parse FreeOTP or FreeOTP+ JSON export. Returns list of token dicts."""

def generate_token(token: dict) -> str:
    """Generate current TOTP or HOTP code. Returns zero-padded string."""

def get_password_from_keyring(vault_path: str) -> str | None:
    """Retrieve stored password from OS keyring. Returns None if not stored."""

def store_password_in_keyring(vault_path: str, password: str) -> None:
    """Store password in OS keyring under service=freeotp-vault, username=vault_path."""

def gdrive_sync(download: bool = False, upload: bool = False) -> bool:
    """Sync vault with Google Drive. Returns True on success."""
```

## Data Formats

### FreeOTP JSON (original app)
```json
{
  "tokens": [
    {
      "issuerExt": "GitHub",
      "label": "alice@example.com",
      "secret": [10, 20, 30, ...],
      "type": "TOTP",
      "algo": "SHA1",
      "digits": 6,
      "period": 30,
      "counter": 0
    }
  ]
}
```
`secret` is a JSON array of signed int8 values (raw bytes).

### FreeOTP+ JSON
Same structure but `secret` may be a base32 string **or** byte array.

### Vault file (encrypted)
`~/.config/freeotp-vault/vault.enc`

Binary layout:
```
[4 bytes magic "FOTV"]
[1 byte version = 1]
[32 bytes scrypt salt]
[12 bytes AES-GCM nonce]
[16 bytes AES-GCM tag  ]  ← appended by GCM, part of ciphertext tail
[N  bytes ciphertext   ]
```
Plaintext inside is UTF-8 JSON: `[{token}, ...]`

## Edge Cases

1. `secret` as signed int8 array → convert via `bytes(b & 0xFF for b in arr)`
2. `secret` as base32 string → pass directly to pyotp
3. HOTP tokens → use stored counter, increment after generation
4. Wrong password → `ValueError` with message, not a traceback dump
5. Vault file missing → clear error telling user to run `init`
6. Keyring unavailable (headless server) → fall back to `getpass` prompt
7. Filter matches zero accounts → warn user, exit 0
8. `period` missing from TOTP token → default to 30 s
9. `digits` missing → default to 6
10. Duplicate `init` → ask confirmation before overwriting vault

## Performance & Constraints
- scrypt params: N=2^17, r=8, p=1 (≈ 0.5 s on modern hardware, acceptable for CLI)
- No plaintext secret ever written to disk or printed in token listing
- Vault JSON stored as compact (no indent) UTF-8

## Version
v0.1.0.1
