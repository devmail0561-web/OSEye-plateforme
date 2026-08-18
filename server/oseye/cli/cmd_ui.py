"""oseye-server ui — configure built UI static file serving."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_SERVER_ENV = Path("/etc/oseye/server.env")
_KEY = "OSEYE_UI_DIR"


def _read_env_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text().splitlines()


def _write_env_file(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    os.chmod(path, 0o640)


def _set_key(path: Path, key: str, value: str) -> None:
    lines = _read_env_file(path)
    updated = False
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(f"{key}=") or stripped == key:
            result.append(f"{key}={value}")
            updated = True
        else:
            result.append(line)
    if not updated:
        result.append(f"{key}={value}")
    _write_env_file(path, result)


def _unset_key(path: Path, key: str) -> bool:
    if not path.exists():
        return False
    lines = _read_env_file(path)
    filtered = [l for l in lines if not (l.strip().startswith(f"{key}=") or l.strip() == key)]
    if len(filtered) == len(lines):
        return False
    _write_env_file(path, filtered)
    return True


def _current_value() -> str | None:
    if os.environ.get(_KEY):
        return os.environ[_KEY]
    for path in [_SERVER_ENV]:
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if line.strip().startswith(f"{_KEY}="):
                return line.strip().split("=", 1)[1]
    return None


# ── subcommands ───────────────────────────────────────────────────────────────

def _cmd_set(args: argparse.Namespace) -> None:
    ui_path = Path(args.path).resolve()
    if not ui_path.is_dir():
        print(f"Error: {ui_path} is not a directory.", file=sys.stderr)
        sys.exit(1)
    if not (ui_path / "index.html").exists():
        print(f"Error: {ui_path}/index.html not found — is this a built UI dist?", file=sys.stderr)
        sys.exit(1)

    _set_key(_SERVER_ENV, _KEY, str(ui_path))
    print(f"UI path set: {ui_path}")
    print("Restart the server for the change to take effect: oseye-server restart")


def _cmd_unset(_args: argparse.Namespace) -> None:
    removed = _unset_key(_SERVER_ENV, _KEY)
    if removed:
        print(f"{_KEY} removed from {_SERVER_ENV}")
        print("Restart the server: oseye-server restart")
    else:
        print(f"{_KEY} was not set.")


def _cmd_status(_args: argparse.Namespace) -> None:
    val = _current_value()
    if val:
        ui_path = Path(val)
        ok = ui_path.is_dir() and (ui_path / "index.html").exists()
        status = "valid" if ok else "INVALID (directory or index.html missing)"
        print(f"UI dir : {val}  [{status}]")
    else:
        print("UI dir : not configured  (API-only mode)")


# ── entry point ───────────────────────────────────────────────────────────────

def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server ui",
        description="Configure built UI static file serving.",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    p_set = sub.add_parser("set", help="Set the UI dist directory")
    p_set.add_argument("path", help="Path to the built UI dist directory")

    sub.add_parser("unset", help="Remove UI dir — server runs API-only")
    sub.add_parser("status", help="Show current UI configuration")

    args = parser.parse_args(argv)
    if args.subcmd == "set":
        _cmd_set(args)
    elif args.subcmd == "unset":
        _cmd_unset(args)
    elif args.subcmd == "status":
        _cmd_status(args)
