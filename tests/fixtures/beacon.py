#!/usr/bin/env python3
"""Harmless simulated-attacker fixture: Beacon (unexpected network).

Simulates an install script phoning home / beaconing over the network.
Attempts a network connection to loopback under the tracee's HOME directory.

SAFETY: Refuses to run unless $HOME/.trapdoor-fake-home exists.
"""
import os
import socket
from pathlib import Path


def main():
    marker = Path.home() / ".trapdoor-fake-home"
    if not marker.is_file():
        raise SystemExit(
            f"SAFETY ERROR: Refusing to run outside a fake HOME. Missing {marker}"
        )

    addr = os.environ.get("BEACON_ADDR", "127.0.0.1")
    port = int(os.environ.get("BEACON_PORT", "9999"))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((addr, port))
        s.close()
    except (OSError, socket.error):
        pass  # Failed connect is still captured at syscall entry


if __name__ == "__main__":
    main()
