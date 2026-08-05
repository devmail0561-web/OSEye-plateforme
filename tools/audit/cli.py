"""
CLI entry point and orchestration for the OSEye Audit Engine.

Usage (from repo root):
    python -m tools.audit                          # full scan, all modes
    python -m tools.audit --mode security          # security patterns only
    python -m tools.audit --mode debug             # debug patterns only
    python -m tools.audit --module M1              # target a single module
    python -m tools.audit --diff                   # incremental (changed files only)
    python -m tools.audit --verify                 # verify all open findings
    python -m tools.audit --verify SEC-0001        # verify one specific finding
    python -m tools.audit --report                 # consolidated report
    python -m tools.audit --list-patterns          # list all patterns
    python -m tools.audit --add-pattern            # add a pattern interactively
    python -m tools.audit --fix SEC-0001 --note "" # mark a finding as fixed
    python -m tools.audit --fp  SEC-0001           # mark as false positive
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime

from .commands import cmd_add_pattern, cmd_false_positive, cmd_mark_fixed, get_sorted_patterns
from .modules import detect_modules, get_changed_files, update_file_hashes, all_source_files
from .persistence import load_patterns, load_state, save_patterns, save_report, save_state
from .reporter import (
    build_json_report,
    print_full_report,
    print_pattern_list,
    print_scan_report,
    print_verify_report,
)
from .scanner import run_scan
from .verifier import verify_findings, verify_regressions


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tools.audit",
        description="OSEye Audit Engine — Security & Debug Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    mode_group = p.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--mode", choices=["all", "security", "debug"], default="all",
        help="Category of patterns to run (default: all)",
    )

    p.add_argument("--module", metavar="Mn", help="Restrict scan to a single module (e.g. M1)")
    p.add_argument("--diff", action="store_true", help="Incremental: scan only changed files")

    # Verify — nargs='?' lets --verify run on all findings, --verify ID on one
    p.add_argument(
        "--verify", nargs="?", const=True, metavar="ID",
        help="Verify open findings are still present (optionally specify a finding ID)",
    )

    p.add_argument("--report", action="store_true", help="Show consolidated report and exit")
    p.add_argument("--list-patterns", action="store_true", help="List all patterns and exit")
    p.add_argument("--add-pattern", action="store_true", help="Add a new pattern interactively")
    p.add_argument("--fix", metavar="ID", help="Mark a finding as fixed")
    p.add_argument("--fp", metavar="ID", help="Mark a finding as false positive")
    p.add_argument("--note", default="", help="Note to attach to --fix or --fp")

    return p


def main() -> int:
    args = build_parser().parse_args()

    state = load_state()
    patterns = load_patterns()

    # ── Read-only / mutation commands ──────────────────────────────────────

    if args.report:
        print_full_report(state)
        return 0

    if args.list_patterns:
        print_pattern_list(get_sorted_patterns(patterns))
        return 0

    if args.add_pattern:
        cmd_add_pattern(patterns)
        return 0

    if args.fix:
        cmd_mark_fixed(state, args.fix, args.note)
        return 0

    if args.fp:
        cmd_false_positive(state, patterns, args.fp, args.note)
        return 0

    # ── Verify ─────────────────────────────────────────────────────────────

    if args.verify is not None:
        finding_id = None if args.verify is True else args.verify
        try:
            confirmed, resolved = verify_findings(state, patterns, finding_id)
        except ValueError as exc:
            print(f"\n  Erreur : {exc}")
            return 2

        print_verify_report(confirmed, resolved, finding_id)
        save_state(state)

        report = {
            "generated_at": datetime.now().isoformat(),
            "label": "verify",
            "finding_id": finding_id,
            "confirmed": [f.id for f in confirmed],
            "resolved": [f.id for f in resolved],
        }
        report_path = save_report(report, f"verify_{finding_id or 'all'}")
        print(f"  Rapport JSON : {report_path}\n")
        return 0

    # ── Scan ───────────────────────────────────────────────────────────────

    print(f"\n{'='*70}")
    label_parts = [f"mode={args.mode}"]
    if args.module:
        label_parts.append(f"module={args.module}")
    if args.diff:
        label_parts.append("diff")
    print(f"  OSEye Audit Engine — {', '.join(label_parts)}")
    print(f"{'='*70}\n")

    # Detect modules
    print("Détection des modules...")
    module_status = detect_modules()
    state.module_status = module_status

    # Regression check on previously fixed findings
    print("Vérification des régressions sur les findings fixés...")
    reopened = verify_regressions(state, patterns)
    if reopened:
        print(f"  ⚠  {len(reopened)} finding(s) réouverts (régression)")

    # Determine changed files for incremental mode
    changed_files = None
    if args.diff:
        changed_files = get_changed_files(state)
        print(f"  Scan incrémental — {len(changed_files)} fichier(s) modifié(s)")
        if not changed_files:
            print("  Aucun fichier modifié depuis le dernier scan — terminé.\n")
            return 0

    # Run scan
    print(f"Scan en cours ({args.mode}{', module '+args.module if args.module else ''})...")
    new_findings = run_scan(
        state=state,
        patterns=patterns,
        mode=args.mode,
        module_filter=args.module,
        changed_files=changed_files,
    )

    # Update file hashes
    update_file_hashes(state, all_source_files())

    # Timestamps
    now = datetime.now().isoformat()
    if args.diff:
        state.last_incremental_scan = now
    else:
        state.last_full_scan = now

    state.scan_history.append({
        "date": now,
        "mode": args.mode,
        "module": args.module,
        "incremental": args.diff,
        "new_findings": len(new_findings),
        "reopened": len(reopened),
    })
    if len(state.scan_history) > 100:
        state.scan_history = state.scan_history[-100:]

    # Save everything
    save_state(state)
    save_patterns(patterns)

    # Console report
    print_scan_report(state, new_findings, reopened, module_status, args.mode, args.diff)

    # JSON report
    label = f"{args.mode}{'_'+args.module if args.module else ''}{'_diff' if args.diff else ''}"
    report_data = build_json_report(state, new_findings, module_status, label)
    report_path = save_report(report_data, label)
    print(f"  Rapport JSON : {report_path}\n")

    # Exit code: non-zero if any BLOCKER is open
    blockers = sum(
        1 for f in state.findings.values()
        if f.status == "open" and f.severity == "BLOCKER"
    )
    return 1 if blockers else 0
