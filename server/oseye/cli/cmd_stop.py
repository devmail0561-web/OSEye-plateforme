"""oseye-server stop — graceful shutdown."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys


def _via_systemd() -> bool:
    """True when the process was started by systemd (INVOCATION_ID is set)."""
    return bool(os.environ.get("INVOCATION_ID"))


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server stop",
        description="Stop the OSEye server.",
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Seconds to wait for graceful shutdown (default: 30)",
    )
    args = parser.parse_args(argv)

    # Systemd path: delegate to systemctl
    if not _via_systemd():
        result = subprocess.run(
            ["systemctl", "stop", "--timeout", str(args.timeout), "oseye-server"],
            check=False,
        )
        sys.exit(result.returncode)

    # In-container / direct path: send SIGTERM to PID 1 (the server process)
    try:
        os.kill(1, signal.SIGTERM)
        print("oseye-server: SIGTERM sent to PID 1")
    except ProcessLookupError:
        print("oseye-server: process not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("oseye-server: permission denied — run as root", file=sys.stderr)
        sys.exit(1)
