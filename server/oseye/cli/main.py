"""oseye-server — server lifecycle CLI."""

from __future__ import annotations

import sys


_USAGE = """\
oseye-server — OSEye server management

Usage:
  oseye-server init      [--certs-dir PATH] [--token-dir PATH] [--hostname H] [--ip IP] [--force]
  oseye-server setup
  oseye-server start     [--validate-only]
  oseye-server validate
  oseye-server update      [--check-only] [--yes] [--pre]
  oseye-server uninstall   [--server] [--agent] [--purge] [--yes] [--dry-run]
  oseye-server version

Commands:
  init        Create system directories and generate PKI (non-interactive, safe to run in CI)
  setup       Interactive configuration wizard — writes server.env and secrets.env
  start       Start the OSEye server (API + gRPC + workers)
  validate    Validate the current configuration and report missing files
  update      Check for and install the latest binary release
  uninstall   Remove server and/or agent from the system (requires root)
  version     Show version
"""


def main(argv: list[str] | None = None) -> None:
    args = argv if argv is not None else sys.argv[1:]

    if not args or args[0] in ("help", "--help", "-h"):
        print(_USAGE)
        return

    cmd, rest = args[0], args[1:]

    if cmd == "init":
        from .cmd_init import run
        run(rest)
    elif cmd == "setup":
        from .cmd_setup import run
        run(rest)
    elif cmd == "start":
        from .cmd_start import run
        run(rest)
    elif cmd == "validate":
        from .cmd_validate import run
        run(rest)
    elif cmd == "update":
        from .cmd_update import run
        run(rest)
    elif cmd == "uninstall":
        from .cmd_uninstall import run
        run(rest)
    elif cmd in ("version", "--version", "-v"):
        try:
            from importlib.metadata import version
            print(f"oseye-server {version('oseye-server')}")
        except Exception:
            print("oseye-server dev")
    else:
        print(f"Unknown command: {cmd}\n", file=sys.stderr)
        print(_USAGE, file=sys.stderr)
        sys.exit(1)
