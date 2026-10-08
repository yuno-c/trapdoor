#!/usr/bin/env python3
"""Harmless simulated-attacker fixture: Persistence.

Simulates an installer establishing persistence by modifying shell startup files.
Writes harmless comments to ~/.bashrc under the tracee's fake HOME.

SAFETY: Refuses to run unless $HOME/.trapdoor-fake-home exists.
"""
from pathlib import Path


def main():
    marker = Path.home() / ".trapdoor-fake-home"
    if not marker.is_file():
        raise SystemExit(
            f"SAFETY ERROR: Refusing to run outside a fake HOME. Missing {marker}"
        )

    bashrc = Path.home() / ".bashrc"
    with bashrc.open("a", encoding="utf-8") as f:
        f.write("\n# trapdoor simulated persistence hook\n")


if __name__ == "__main__":
    main()
