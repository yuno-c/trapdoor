#!/usr/bin/env python3
"""Harmless simulated-attacker fixture: Credential theft.

Simulates an install script attempting to harvest SSH private keys.
Touches/reads ~/.ssh/id_ed25519 under the tracee's HOME directory.
"""
from pathlib import Path


def main():
    marker = Path.home() / ".trapdoor-fake-home"
    if not marker.is_file():
        raise SystemExit(
            f"SAFETY ERROR: Refusing to run outside a fake HOME. Missing {marker}"
        )

    target = Path.home() / ".ssh" / "id_ed25519"
    try:
        _ = target.read_bytes()
    except OSError:
        pass


if __name__ == "__main__":
    main()
