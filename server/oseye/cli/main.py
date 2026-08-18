"""oseye-server — server lifecycle CLI."""

from __future__ import annotations

import sys

_USAGE = """\
oseye-server — OSEye server management

Usage:
  oseye-server init      [--certs-dir PATH] [--token-dir PATH] [--hostname H] [--ip IP] [--force]
  oseye-server setup
  oseye-server start     [--validate-only]
  oseye-server stop      [--timeout N]
  oseye-server restart   [--timeout N]
  oseye-server status
  oseye-server ui set <PATH>
  oseye-server ui unset
  oseye-server ui url <URL>
  oseye-server ui url --unset
  oseye-server ui status
  oseye-server api enable
  oseye-server api disable
  oseye-server api status
  oseye-server plugin upload <FILE> [--sig FILE] [--no-verify]
  oseye-server plugin list
  oseye-server enrollment token create  [--valid-hours N]
  oseye-server enrollment token list
  oseye-server enrollment token revoke  <TOKEN_ID>
  oseye-server user create <username> --role admin|analyst [--password PW] [--force]
  oseye-server user passwd <username> [--password PW]
  oseye-server user delete <username>
  oseye-server user list
  oseye-server validate
  oseye-server update      [--check-only] [--yes] [--pre]
  oseye-server uninstall   [--server] [--agent] [--purge] [--yes] [--dry-run]
  oseye-server version

Commands:
  init        Create system directories and generate PKI (non-interactive, safe to run in CI)
  setup       Interactive configuration wizard — writes server.env and secrets.env
  start       Start the OSEye server (API + gRPC + workers)
  stop        Gracefully stop the server (SIGTERM / systemctl stop)
  restart     Stop then start the server (systemctl restart)
  status      Show server status and API health
  ui          Configure UI serving and UI server URL (set/unset/url/status)
  api         Enable/disable management REST API (enable/disable/status)
  plugin      Manage plugins without the UI (upload/list)
  validate    Validate the current configuration and report missing files
  update      Check for and install the latest binary release
  enrollment  Manage enrollment tokens (token create/list/revoke)
  user        Manage local users (create, passwd, delete, list)
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
    elif cmd == "stop":
        from .cmd_stop import run
        run(rest)
    elif cmd == "restart":
        from .cmd_restart import run
        run(rest)
    elif cmd == "status":
        from .cmd_status import run
        run(rest)
    elif cmd == "ui":
        from .cmd_ui import run
        run(rest)
    elif cmd == "api":
        from .cmd_api import run
        run(rest)
    elif cmd == "plugin":
        from .cmd_plugin import run
        run(rest)
    elif cmd == "enrollment":
        from .cmd_enrollment import run
        run(rest)
    elif cmd == "user":
        from .cmd_user import run
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
