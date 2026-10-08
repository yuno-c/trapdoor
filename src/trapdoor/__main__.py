"""Allow `python -m trapdoor` (delegates to trapdoor.cli:main)."""

from trapdoor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
