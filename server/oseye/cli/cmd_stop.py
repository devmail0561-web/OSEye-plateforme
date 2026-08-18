"""oseye-server stop — graceful shutdown."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys

_SYSTEMCTL = "/usr/bin/systemctl"


def _systemctl_available() -> bool:
    return os.path.isfile(_SYSTEMCTL)


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

    if _systemctl_available():
        result = subprocess.run(
            ["systemctl", "stop", "--timeout", str(args.timeout), "oseye-server"],
            check=False,
        )
        sys.exit(result.returncode)

    # Container / no-systemd path: send SIGTERM to PID 1
    try:
        os.kill(1, signal.SIGTERM)
        print("oseye-server: SIGTERM sent to PID 1")
    except ProcessLookupError:
        print("oseye-server: process not found", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print("oseye-server: permission denied — run as root", file=sys.stderr)
        sys.exit(1)
