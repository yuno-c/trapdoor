#!/usr/bin/env python3
"""Harmless control fixture: Clean / ordinary work.

Simulates a legitimate install script doing normal build work:
creating files strictly inside the project directory and reading normal system data.
Must produce ZERO rule hits.

SAFETY: Refuses to run unless $HOME/.trapdoor-fake-home exists.
"""
from pathlib import Path


def main():
    marker = Path.home() / ".trapdoor-fake-home"
    if not marker.is_file():
        raise SystemExit(
            f"SAFETY ERROR: Refusing to run outside a fake HOME. Missing {marker}"
        )

    # Normal build work within project directory
    build_dir = Path.cwd() / "build"
    build_dir.mkdir(exist_ok=True)
    out_file = build_dir / "artifact.txt"
    out_file.write_text("compiled artifact data\n")
    _ = out_file.read_text()


if __name__ == "__main__":
    main()
