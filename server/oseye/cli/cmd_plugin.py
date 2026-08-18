"""oseye-server plugin — manage plugins from the CLI (no server required)."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path


def _make_manager():
    from oseye.config import Settings
    from oseye.plugin.manager import PluginManager
    from oseye.plugin.verifier import PluginVerifier

    s = Settings()
    plugins_dir = Path(s.plugins_dir)
    keys_dir = Path(s.plugin_keys_dir)

    verifier: PluginVerifier | None = None
    if keys_dir.is_dir() and any(keys_dir.glob("*.pem")):
        verifier = PluginVerifier(keys_dir)

    return PluginManager(
        plugins_dir=plugins_dir,
        ipc_socket=s.plugin_ipc_socket,
        verifier=verifier,
        require_signature=s.plugin_require_signature,
    )


# ── upload ────────────────────────────────────────────────────────────────────

async def _do_upload(path: Path, sig: Path | None, verify: bool) -> None:
    manager = _make_manager()

    if sig is not None:
        import shutil
        expected_sig = path.with_suffix(".sig")
        if sig != expected_sig:
            shutil.copy2(sig, expected_sig)
            print(f"  Copied signature → {expected_sig}")

    info = await manager.install(path, verify=verify)
    print(f"\nPlugin installed:")
    print(f"  Name   : {info.name}")
    print(f"  Path   : {info.path}")
    print(f"  Status : {info.status}")
    if info.error:
        print(f"  Error  : {info.error}", file=sys.stderr)
        sys.exit(1)
    print("\nRestart the server to enable the plugin, or use the UI.")


def _cmd_upload(args: argparse.Namespace) -> None:
    path = Path(args.path).resolve()
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    if path.suffix != ".py":
        print(f"Error: plugin must be a .py file, got: {path.name}", file=sys.stderr)
        sys.exit(1)

    sig = Path(args.sig).resolve() if args.sig else None
    if sig and not sig.exists():
        print(f"Error: signature file not found: {sig}", file=sys.stderr)
        sys.exit(1)

    verify = not args.no_verify
    try:
        asyncio.run(_do_upload(path, sig, verify))
    except (ValueError, FileNotFoundError) as exc:
        print(f"Upload failed: {exc}", file=sys.stderr)
        sys.exit(1)


# ── list ──────────────────────────────────────────────────────────────────────

def _cmd_list(_args: argparse.Namespace) -> None:
    manager = _make_manager()
    plugins = manager.list()

    if not plugins:
        print("No plugins installed.")
        return

    col = max(len(p.name) for p in plugins)
    print(f"\n{'Name':<{col}}  {'Status':<10}  {'PID':<6}  Path")
    print("-" * 72)
    for p in plugins:
        pid = str(p.pid) if p.pid is not None else "-"
        err = f"  ! {p.error}" if p.error else ""
        print(f"{p.name:<{col}}  {p.status:<10}  {pid:<6}  {p.path}{err}")
    print()


# ── entry point ───────────────────────────────────────────────────────────────

def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server plugin",
        description="Manage plugins from the CLI (server does not need to be running).",
    )
    sub = parser.add_subparsers(dest="subcmd", required=True)

    p_upload = sub.add_parser("upload", help="Upload and install a plugin file")
    p_upload.add_argument("path", help="Path to the plugin .py file")
    p_upload.add_argument(
        "--sig", metavar="FILE",
        help="Signature file (.sig). Defaults to <plugin>.sig in the same directory.",
    )
    p_upload.add_argument(
        "--no-verify", action="store_true",
        help="Skip signature verification (only valid when OSEYE_PLUGIN_REQUIRE_SIGNATURE=false)",
    )

    sub.add_parser("list", help="List installed plugins")

    args = parser.parse_args(argv)
    if args.subcmd == "upload":
        _cmd_upload(args)
    elif args.subcmd == "list":
        _cmd_list(args)
