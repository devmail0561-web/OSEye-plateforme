"""oseye-server ui — configure built UI static file serving."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_SERVER_ENV = Path("/etc/oseye/server.env")
_KEY_DIR = "OSEYE_UI_DIR"
_KEY_URL = "OSEYE_UI_URL"
_KEY = _KEY_DIR  # compat avec les helpers existants


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
    filtered = [ln for ln in lines if not (ln.strip().startswith(f"{key}=") or ln.strip() == key)]
    if len(filtered) == len(lines):
        return False
    _write_env_file(path, filtered)
    return True


def _current_value(key: str) -> str | None:
    if os.environ.get(key):
        return os.environ[key]
    if not _SERVER_ENV.exists():
        return None
    for line in _SERVER_ENV.read_text().splitlines():
        if line.strip().startswith(f"{key}="):
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

    _set_key(_SERVER_ENV, _KEY_DIR, str(ui_path))
    print(f"UI dir set: {ui_path}")
    print("Restart the server for the change to take effect: oseye-server restart")


def _cmd_unset(_args: argparse.Namespace) -> None:
    removed = _unset_key(_SERVER_ENV, _KEY_DIR)
    if removed:
        print(f"{_KEY_DIR} removed from {_SERVER_ENV}")
        print("Restart the server: oseye-server restart")
    else:
        print(f"{_KEY_DIR} was not set.")


def _cmd_url(args: argparse.Namespace) -> None:
    if args.unset:
        removed = _unset_key(_SERVER_ENV, _KEY_URL)
        if removed:
            print(f"{_KEY_URL} removed from {_SERVER_ENV}")
            print("Restart the server: oseye-server restart")
        else:
            print(f"{_KEY_URL} was not set.")
        return

    url = args.url.rstrip("/")
    if not (url.startswith("http://") or url.startswith("https://")):
        print("Error: URL must start with http:// or https://", file=sys.stderr)
        sys.exit(1)

    _set_key(_SERVER_ENV, _KEY_URL, url)
    print(f"UI URL set: {url}")
    print("  CORS: {url} automatically added to allow_origins")
    print("  Redirect: GET / → {url} (when management API is active)")
    print("Restart the server: oseye-server restart")


def _cmd_status(_args: argparse.Namespace) -> None:
    dir_val = _current_value(_KEY_DIR)
    url_val = _current_value(_KEY_URL)

    if dir_val:
        ui_path = Path(dir_val)
        ok = ui_path.is_dir() and (ui_path / "index.html").exists()
        status = "valid" if ok else "INVALID (directory or index.html missing)"
        print(f"UI dir : {dir_val}  [{status}]")
    else:
        print("UI dir : not configured  (UI not served from this server)")

    if url_val:
        print(f"UI URL : {url_val}  [CORS configured, redirect from /]")
    else:
        print("UI URL : not configured")


# ── entry point ───────────────────────────────────────────────────────────────

def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server ui",
        description="Configure UI serving and UI server URL.",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    p_set = sub.add_parser("set", help="Set the UI dist directory (local serving)")
    p_set.add_argument("path", help="Path to the built UI dist directory")

    sub.add_parser("unset", help="Remove OSEYE_UI_DIR — stop serving UI from this server")

    p_url = sub.add_parser("url", help="Set the external UI server URL (OSEYE_UI_URL)")
    p_url.add_argument("url", nargs="?", help="URL of the UI server (e.g. https://ui.example.com)")
    p_url.add_argument("--unset", action="store_true", help="Remove OSEYE_UI_URL")

    sub.add_parser("status", help="Show current UI configuration")

    args = parser.parse_args(argv)
    if args.subcmd == "set":
        _cmd_set(args)
    elif args.subcmd == "unset":
        _cmd_unset(args)
    elif args.subcmd == "url":
        if not args.unset and not args.url:
            parser.error("oseye-server ui url requires a URL or --unset")
        _cmd_url(args)
    elif args.subcmd == "status":
        _cmd_status(args)
