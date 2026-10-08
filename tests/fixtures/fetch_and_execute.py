#!/usr/bin/env python3
"""Harmless simulated-attacker fixture: Fetch-and-execute.

Simulates a dropper that writes a secondary payload to disk and executes it.
Writes a harmless script in the project directory and invokes it.

SAFETY: Refuses to run unless $HOME/.trapdoor-fake-home exists.
"""
import subprocess
import sys
from pathlib import Path


def main():
    marker = Path.home() / ".trapdoor-fake-home"
    if not marker.is_file():
        raise SystemExit(
            f"SAFETY ERROR: Refusing to run outside a fake HOME. Missing {marker}"
        )

    # Write a harmless secondary payload inside the current directory
    payload = Path.cwd() / "stage2_payload.sh"
    payload.write_text("#!/bin/sh\n# harmless stage 2\nexit 0\n")
    payload.chmod(0o755)

    # Execute the file that was just written
    subprocess.run([str(payload)], check=False)


if __name__ == "__main__":
    main()
