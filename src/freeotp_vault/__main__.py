from pathlib import Path

from .cli import main as _main

DEFAULT_VAULT_DIR = Path.home() / ".config" / "freeotp-vault"


def main() -> int:
    """CLI entry point for freeotp-vault."""
    DEFAULT_VAULT_DIR.mkdir(parents=True, exist_ok=True)
    _main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
