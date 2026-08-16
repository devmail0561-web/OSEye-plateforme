"""oseye-server uninstall — remove server and/or agent from the system."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


_SYSTEMCTL = "/usr/bin/systemctl"

# ── install paths ────────────────────────────────────────────────────────────

@dataclass
class _Component:
    name: str
    service: str                          # systemd unit name (without .service)
    service_file: Path                    # unit file on disk
    binaries: list[Path]                  # executables to remove


_SERVER = _Component(
    name="server",
    service="oseye-server",
    service_file=Path("/usr/lib/systemd/system/oseye-server.service"),
    binaries=[Path(sys.executable)] if getattr(sys, "frozen", False)
              else [Path("/usr/bin/oseye-server")],
)

_AGENT = _Component(
    name="agent",
    service="oseye-agent",
    service_file=Path("/usr/lib/systemd/system/oseye-agent.service"),
    binaries=[Path("/usr/bin/oseye-agent"), Path("/usr/bin/oseye-config")],
)

_SHARED_DIRS: list[Path] = [
    Path("/etc/oseye"),
    Path("/var/lib/oseye"),
]


# ── helpers ──────────────────────────────────────────────────────────────────

def _require_root() -> None:
    if os.getuid() != 0:
        print("Error: uninstall requires root privileges.", file=sys.stderr)
        print("Run with:  sudo oseye-server uninstall", file=sys.stderr)
        sys.exit(1)


def _systemd_available() -> bool:
    return os.path.isfile(_SYSTEMCTL)


def _service_active(service: str) -> bool:
    try:
        result = subprocess.run(
            [_SYSTEMCTL, "is-active", "--quiet", service],
            check=False, capture_output=True,
        )
        return result.returncode == 0
    except OSError:
        return False


def _stop_disable(service: str, dry_run: bool) -> None:
    if not _systemd_available():
        return
    for action in ("stop", "disable"):
        print(f"  systemctl {action} {service}")
        if not dry_run:
            subprocess.run([_SYSTEMCTL, action, service],
                           check=False, capture_output=True)


def _remove_path(p: Path, dry_run: bool) -> None:
    if not p.exists() and not p.is_symlink():
        return
    print(f"  rm  {p}")
    if dry_run:
        return
    if p.is_dir():
        shutil.rmtree(p)
    else:
        p.unlink()


def _daemon_reload(dry_run: bool) -> None:
    if not _systemd_available():
        return
    print("  systemctl daemon-reload")
    if not dry_run:
        subprocess.run([_SYSTEMCTL, "daemon-reload"],
                       check=False, capture_output=True)


def _confirm(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


# ── uninstall logic ──────────────────────────────────────────────────────────

def _uninstall_component(comp: _Component, dry_run: bool) -> None:
    print(f"\n[{comp.name}]")

    if _service_active(comp.service):
        _stop_disable(comp.service, dry_run)
    elif _systemd_available():
        _stop_disable(comp.service, dry_run)

    for binary in comp.binaries:
        _remove_path(binary, dry_run)

    _remove_path(comp.service_file, dry_run)
    _daemon_reload(dry_run)


def _uninstall_shared(purge: bool, both: bool, dry_run: bool, yes: bool) -> None:
    if not purge:
        return

    existing = [d for d in _SHARED_DIRS if d.exists()]
    if not existing:
        return

    if not both:
        print(
            "\nWarning: /etc/oseye and /var/lib/oseye are shared between the "
            "server and agent.\n"
            "Only one component is being uninstalled — removing them may break "
            "the remaining component."
        )

    print("\n[shared data]")
    for d in existing:
        print(f"  rm -rf  {d}")

    if not yes and not dry_run:
        if not _confirm("Permanently delete config and data? [y/N] "):
            print("Skipped shared directories.")
            return

    if not dry_run:
        for d in existing:
            _remove_path(d, dry_run=False)


# ── entry point ──────────────────────────────────────────────────────────────

def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server uninstall",
        description="Remove oseye-server and/or oseye-agent from this system.",
    )
    parser.add_argument("--server", action="store_true", help="Uninstall the server")
    parser.add_argument("--agent", action="store_true", help="Uninstall the agent")
    parser.add_argument(
        "--purge", action="store_true",
        help="Also remove config (/etc/oseye) and data (/var/lib/oseye)",
    )
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be removed without making changes")
    args = parser.parse_args(argv)

    _require_root()

    # Interactive target selection if neither flag given
    if not args.server and not args.agent:
        print("What do you want to uninstall?")
        print("  1) Server only")
        print("  2) Agent only")
        print("  3) Both")
        try:
            choice = input("Choice [1/2/3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            sys.exit(0)
        args.server = choice in ("1", "3")
        args.agent = choice in ("2", "3")
        if not args.server and not args.agent:
            print("Invalid choice — aborted.")
            sys.exit(1)

    targets: list[_Component] = []
    if args.server:
        targets.append(_SERVER)
    if args.agent:
        targets.append(_AGENT)

    # Summary
    label = " + ".join(c.name for c in targets)
    purge_note = " (+ config/data)" if args.purge else ""
    dry_note = "  [DRY RUN — no changes will be made]" if args.dry_run else ""
    print(f"\nUninstall: {label}{purge_note}{dry_note}\n")

    paths_to_remove: list[str] = []
    for comp in targets:
        for b in comp.binaries:
            if b.exists():
                paths_to_remove.append(str(b))
        if comp.service_file.exists():
            paths_to_remove.append(str(comp.service_file))
    if args.purge:
        paths_to_remove += [str(d) for d in _SHARED_DIRS if d.exists()]

    if paths_to_remove:
        print("Files/directories that will be removed:")
        for p in paths_to_remove:
            print(f"  {p}")
    else:
        print("Nothing found to remove.")
        return

    if not args.yes and not args.dry_run:
        if not _confirm(f"\nProceed with uninstall of {label}? [y/N] "):
            print("Aborted.")
            sys.exit(0)

    for comp in targets:
        _uninstall_component(comp, args.dry_run)

    both = args.server and args.agent
    _uninstall_shared(args.purge, both, args.dry_run, args.yes)

    if args.dry_run:
        print("\nDry run complete — nothing was removed.")
    else:
        print(f"\nUninstall of {label} complete.")
