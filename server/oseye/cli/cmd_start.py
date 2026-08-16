"""oseye-server start — start the OSEye server."""

from __future__ import annotations

import argparse
import sys


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server start",
        description="Start the OSEye server (API + gRPC + workers).",
    )
    parser.add_argument("--validate-only", action="store_true",
                        help="Validate configuration then exit without starting")
    args = parser.parse_args(argv)

    if args.validate_only:
        from .cmd_validate import run as validate
        validate([])
        return

    from oseye.main import main
    main()
