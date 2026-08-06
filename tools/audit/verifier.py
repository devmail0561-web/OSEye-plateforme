"""
Finding verifier.

Three distinct operations:
  - verify_regressions      : re-scan 'fixed' findings to catch regressions
  - verify_findings         : re-scan 'open' findings (all or one by ID)
  - verify_findings_for_files : re-scan only findings whose file is in the
                               given set — used when auditing a PR/diff scope

All operations mutate state in place and return (confirmed, resolved) or
a list of reopened findings.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from .models import ROOT, AuditState, Finding, Pattern
from .scanner import scan_inverse, scan_regex, scan_script

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pattern_map(patterns: list[Pattern]) -> dict[str, Pattern]:
    return {p.id: p for p in patterns}


def _locate_finding(state: AuditState, finding_id: str) -> Finding | None:
    for f in state.findings.values():
        if f.id == finding_id:
            return f
    return None


def _still_present(finding: Finding, pattern: Pattern) -> bool:
    """
    Re-run the pattern scoped to finding.file and check whether the finding
    is still detectable.

    For regex patterns: search for the regex around ±5 lines of finding.line.
    For script patterns: check if finding.file appears in the script output.
    For inverse patterns: re-apply inverse logic on finding.file.
    """
    fpath = ROOT / finding.file

    if pattern.is_inverse():
        # Inverse: the finding was about an *absence* in this file.
        # It is still present if the absence persists.
        results = scan_inverse(pattern)
        return any(str(finding.file) in str(r[0]) for r in results)

    if pattern.script:
        results = scan_script(pattern)
        return any(finding.file in str(r[0]) for r in results)

    # Regex pattern
    if not fpath.exists():
        # File deleted — consider the finding resolved
        return False

    hits = scan_regex(pattern, [fpath])
    if not hits:
        return False

    # If we have a line number, be tolerant of ±5 line drift from edits
    if finding.line > 0:
        target_lines = {finding.line + d for d in range(-5, 6)}
        return any(line_no in target_lines for _, line_no, _ in hits)

    # No line info: presence of any hit means it's still there
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def verify_regressions(
    state: AuditState,
    patterns: list[Pattern],
) -> list[Finding]:
    """
    Re-scan findings with status='fixed' to detect regressions.
    Re-opens any that are still detectable.
    Returns the list of re-opened findings.
    """
    pmap = _pattern_map(patterns)
    now = datetime.now(UTC).isoformat()
    reopened: list[Finding] = []

    for finding in state.findings.values():
        if finding.status != "fixed":
            continue
        pat = pmap.get(finding.pattern_id)
        if not pat or not pat.enabled:
            continue
        if _still_present(finding, pat):
            finding.status = "open"
            finding.last_seen = now
            finding.occurrences += 1
            finding.fix_note = f"Régression détectée le {now}"
            reopened.append(finding)

    return reopened


def verify_findings(
    state: AuditState,
    patterns: list[Pattern],
    finding_id: str | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """
    Re-scan open findings to confirm they are still present or auto-close them.

    Args:
        state:       audit state (mutated in place)
        patterns:    all known patterns
        finding_id:  if given, verify only this specific finding ID;
                     otherwise verify all open findings

    Returns:
        (confirmed, resolved)
        confirmed — findings still present (last_seen updated)
        resolved  — findings no longer detectable (status set to 'fixed')

    Raises:
        ValueError if finding_id is given but not found or not open.
    """
    pmap = _pattern_map(patterns)
    now = datetime.now(UTC).isoformat()
    confirmed: list[Finding] = []
    resolved: list[Finding] = []

    # Build the work list
    if finding_id is not None:
        target = _locate_finding(state, finding_id)
        if target is None:
            raise ValueError(f"Finding '{finding_id}' introuvable.")
        if target.status != "open":
            raise ValueError(
                f"Finding '{finding_id}' a le statut '{target.status}' — seuls les findings 'open' peuvent être vérifiés."
            )
        work = [target]
    else:
        work = [f for f in state.findings.values() if f.status == "open"]

    for finding in work:
        pat = pmap.get(finding.pattern_id)
        if pat is None:
            # Pattern deleted — keep finding open, just skip
            continue
        if not pat.enabled:
            continue

        if _still_present(finding, pat):
            finding.last_seen = now
            confirmed.append(finding)
        else:
            finding.status = "fixed"
            finding.last_seen = now
            finding.fix_note = (
                finding.fix_note + f" | Auto-résolu le {now}"
                if finding.fix_note
                else f"Auto-résolu par vérification le {now}"
            )
            resolved.append(finding)

    state.last_verify = now
    return confirmed, resolved


def verify_findings_for_files(
    state: AuditState,
    patterns: list[Pattern],
    file_paths: list[Path],
) -> tuple[list[Finding], list[Finding]]:
    """
    Re-scan only the open findings whose file is in file_paths.

    Called automatically during --diff scans so that changing a file
    also triggers re-verification of existing findings on that file.

    Args:
        state:       audit state (mutated in place)
        patterns:    all known patterns
        file_paths:  files to scope the verification to (absolute or ROOT-relative)

    Returns:
        (confirmed, resolved) — same semantics as verify_findings()
    """
    pmap = _pattern_map(patterns)
    now = datetime.now(UTC).isoformat()
    confirmed: list[Finding] = []
    resolved: list[Finding] = []

    # Normalise paths to repo-relative strings for comparison
    rel_paths: set[str] = set()
    for p in file_paths:
        try:
            rel_paths.add(str(p.relative_to(ROOT)))
        except ValueError:
            rel_paths.add(str(p))

    in_scope = [
        f for f in state.findings.values()
        if f.status == "open" and f.file in rel_paths
    ]

    for finding in in_scope:
        pat = pmap.get(finding.pattern_id)
        if pat is None or not pat.enabled:
            continue

        if _still_present(finding, pat):
            finding.last_seen = now
            confirmed.append(finding)
        else:
            finding.status = "fixed"
            finding.last_seen = now
            finding.fix_note = (
                finding.fix_note + f" | Auto-résolu le {now}"
                if finding.fix_note
                else f"Auto-résolu par vérification le {now}"
            )
            resolved.append(finding)

    if in_scope:
        state.last_verify = now

    return confirmed, resolved
