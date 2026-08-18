"""oseye-server restart — stop then start."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

_SYSTEMCTL = "/usr/bin/systemctl"


def _systemctl_available() -> bool:
    return os.path.isfile(_SYSTEMCTL)


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server restart",
        description="Restart the OSEye server.",
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Seconds to wait for graceful stop before restart (default: 30)",
    )
    args = parser.parse_args(argv)

    if _systemctl_available():
        result = subprocess.run(
            ["systemctl", "restart", "--timeout", str(args.timeout), "oseye-server"],
            check=False,
        )
        sys.exit(result.returncode)

    # Container / no-systemd path: stop (Docker restart policy handles the restart)
    from .cmd_stop import run as stop_run
    stop_run(["--timeout", str(args.timeout)])
