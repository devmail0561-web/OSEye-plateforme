"""oseye-server restart — stop then start."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys


def _via_systemd() -> bool:
    return bool(os.environ.get("INVOCATION_ID"))


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

    if not _via_systemd():
        result = subprocess.run(
            ["systemctl", "restart", "--timeout", str(args.timeout), "oseye-server"],
            check=False,
        )
        sys.exit(result.returncode)

    # In-container: stop then start (Docker restart policy handles the restart)
    from .cmd_stop import run as stop_run
    stop_run(["--timeout", str(args.timeout)])
