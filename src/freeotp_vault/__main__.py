import sys
from .cli import main as _main


def main() -> int:
    """CLI entry point for freeotp-vault."""
    _main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())