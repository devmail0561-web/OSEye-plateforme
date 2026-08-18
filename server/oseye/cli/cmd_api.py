"""oseye-server api — enable/disable the management REST API."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

_SERVER_ENV = Path("/etc/oseye/server.env")
_KEY = "OSEYE_MANAGEMENT_API_ENABLED"


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text().splitlines()


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(path, 0o640)


def _set_value(value: str) -> None:
    lines = _read_lines(_SERVER_ENV)
    updated = False
    result = []
    for line in lines:
        if line.strip().startswith(f"{_KEY}="):
            result.append(f"{_KEY}={value}")
            updated = True
        else:
            result.append(line)
    if not updated:
        result.append(f"{_KEY}={value}")
    _write_lines(_SERVER_ENV, result)


def _current_value() -> str | None:
    if os.environ.get(_KEY):
        return os.environ[_KEY]
    if not _SERVER_ENV.exists():
        return None
    for line in _SERVER_ENV.read_text().splitlines():
        if line.strip().startswith(f"{_KEY}="):
            return line.strip().split("=", 1)[1]
    return None


def _cmd_enable(_args: argparse.Namespace) -> None:
    _set_value("true")
    print(f"{_KEY}=true written to {_SERVER_ENV}")
    print("Management API endpoints will be active after restart:")
    print("  auth, alerts, decisions, rules, cases, agents, plugins…")
    print("Restart: oseye-server restart")


def _cmd_disable(_args: argparse.Namespace) -> None:
    _set_value("false")
    print(f"{_KEY}=false written to {_SERVER_ENV}")
    print("Only agent-facing endpoints will be active after restart:")
    print("  GET /api/v1/health")
    print("  POST /api/v1/enroll/*")
    print("  gRPC :{OSEYE_GRPC_PORT}")
    print("Restart: oseye-server restart")


def _cmd_status(_args: argparse.Namespace) -> None:
    val = _current_value()
    if val is None:
        active = False
        source = "default (not set)"
    else:
        active = val.lower() in ("true", "1", "yes")
        source = str(_SERVER_ENV) if not os.environ.get(_KEY) else "environment"

    status = "ENABLED" if active else "disabled (agent-only)"
    print(f"Management API : {status}  [{source}]")
    if active:
        print("  Endpoints : auth, alerts, decisions, rules, cases, agents, plugins…")
    else:
        print("  Endpoints : /health, /enroll/* only")
        print("  To enable : oseye-server api enable")


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server api",
        description="Enable or disable the management REST API.",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    sub.add_parser("enable", help="Enable the management API (OSEYE_MANAGEMENT_API_ENABLED=true)")
    sub.add_parser("disable", help="Disable — agent-only mode (OSEYE_MANAGEMENT_API_ENABLED=false)")
    sub.add_parser("status", help="Show current management API status")

    args = parser.parse_args(argv)
    if args.subcmd == "enable":
        _cmd_enable(args)
    elif args.subcmd == "disable":
        _cmd_disable(args)
    elif args.subcmd == "status":
        _cmd_status(args)
