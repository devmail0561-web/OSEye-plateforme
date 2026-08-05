"""Scan engine: regex patterns, shell scripts, inverse patterns, finding lifecycle."""

from __future__ import annotations

import re
import subprocess
from datetime import datetime
from pathlib import Path

from .models import ROOT, AuditState, Finding, Pattern, SEVERITY_ORDER
from .modules import resolve_globs


# ---------------------------------------------------------------------------
# Low-level scan primitives
# ---------------------------------------------------------------------------

def scan_regex(pattern: Pattern, files: list[Path]) -> list[tuple[Path, int, str]]:
    """Search for pattern.regex in each file. Returns (path, line_no, line_text)."""
    if not pattern.regex or not files:
        return []
    rx = re.compile(pattern.regex, re.IGNORECASE)
    results: list[tuple[Path, int, str]] = []
    for path in files:
        try:
            for i, line in enumerate(path.read_text(errors="ignore").splitlines(), 1):
                if rx.search(line):
                    results.append((path, i, line.strip()))
        except Exception:
            pass
    return results


def scan_script(pattern: Pattern) -> list[tuple[str, int, str]]:
    """Run pattern.script, return each output line as a finding location."""
    if not pattern.script:
        return []
    cmd = pattern.script.replace("{ROOT}", str(ROOT))
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30, cwd=ROOT,
        )
        return [
            (line.strip(), -1, line.strip())
            for line in result.stdout.splitlines()
            if line.strip()
        ]
    except Exception:
        return []


def scan_inverse(pattern: Pattern) -> list[tuple[str, int, str]]:
    """Inverse pattern: fire when regex is ABSENT from target files."""
    targets = resolve_globs(pattern.targets)
    if not targets:
        return []
    rx = re.compile(pattern.regex, re.IGNORECASE)
    results: list[tuple[str, int, str]] = []
    for path in targets:
        try:
            content = path.read_text(errors="ignore")
            if not rx.search(content):
                rel = str(path.relative_to(ROOT))
                results.append((rel, -1, f"Pattern '{pattern.regex}' absent de {path.name}"))
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Finding ID counter
# ---------------------------------------------------------------------------

def _next_id(state: AuditState, category: str) -> str:
    prefix = "SEC" if category == "security" else "DBG"
    state.finding_counter[prefix] = state.finding_counter.get(prefix, 0) + 1
    return f"{prefix}-{state.finding_counter[prefix]:04d}"


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------

def run_scan(
    state: AuditState,
    patterns: list[Pattern],
    mode: str = "all",
    module_filter: str | None = None,
    changed_files: list[Path] | None = None,
) -> list[Finding]:
    """
    Execute all matching patterns and update state.findings in place.

    Args:
        state:          audit state (mutated)
        patterns:       list of all known patterns
        mode:           "all" | "security" | "debug"
        module_filter:  if set, only run patterns for this module (or "*")
        changed_files:  if set, restrict regex scans to these files (incremental)

    Returns:
        List of newly created or re-opened findings.
    """
    now = datetime.now().isoformat()
    new_findings: list[Finding] = []

    active = [
        p for p in patterns
        if p.enabled
        and (mode == "all" or p.category == mode)
        and (module_filter is None or p.module in (module_filter, "*"))
    ]

    for pattern in active:
        raw: list[tuple] = []

        if pattern.is_inverse():
            raw = scan_inverse(pattern)
        elif pattern.script:
            raw = scan_script(pattern)
        else:
            # Select target files, possibly filtered to changed_files
            targets = resolve_globs(pattern.targets)
            if changed_files is not None:
                targets = [f for f in targets if f in set(changed_files)]
            raw = scan_regex(pattern, targets)

        if not raw:
            continue

        pattern.hit_count += 1

        for file_or_str, line_num, text in raw:
            rel = (
                str(file_or_str.relative_to(ROOT))
                if isinstance(file_or_str, Path)
                else str(file_or_str)
            )
            key = f"{pattern.id}::{rel}::{line_num}"

            if key in state.findings:
                existing = state.findings[key]
                existing.last_seen = now
                existing.occurrences += 1
                if existing.status == "fixed":
                    existing.status = "open"
                    existing.fix_note = f"Régression détectée le {now}"
                    new_findings.append(existing)
            else:
                fid = _next_id(state, pattern.category)
                finding = Finding(
                    id=fid,
                    category=pattern.category,
                    severity=pattern.severity,
                    module=pattern.module,
                    file=rel,
                    line=line_num,
                    pattern_id=pattern.id,
                    title=pattern.name,
                    detail=f"{pattern.description}\n  Contexte: {text[:200]}",
                    first_seen=now,
                    last_seen=now,
                )
                state.findings[key] = finding
                new_findings.append(finding)

    return sorted(new_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
