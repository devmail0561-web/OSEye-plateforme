"""Console output and JSON report generation."""

from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from .models import SEVERITY_COLOR, SEVERITY_ORDER, AuditState, Finding, Pattern

C = SEVERITY_COLOR
R = C["RESET"]
G = C["GREEN"]
Y = C["YELLOW"]
GR = C["GREY"]
B = C["BOLD"]


def _bar(char: str = "─", width: int = 70) -> str:
    return char * width


# ---------------------------------------------------------------------------
# Post-scan report
# ---------------------------------------------------------------------------

def print_scan_report(
    state: AuditState,
    new_findings: list[Finding],
    reopened: list[Finding],
    module_status: dict[str, str],
    mode: str,
    incremental: bool,
    auto_resolved: list[Finding] | None = None,
) -> None:
    print(f"\n{B}{_bar('═')}{R}")
    print(f"  {B}OSEye Audit — mode={mode}{'  [incrémental]' if incremental else ''} — {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}{R}")
    print(f"{B}{_bar('═')}{R}\n")

    # Modules
    print(f"{B}MODULES:{R}")
    icons = {"implemented": (G, "✓"), "partial": (Y, "~"), "absent": (GR, "○")}
    for mod in sorted(module_status):
        col, icon = icons.get(module_status[mod], ("", "?"))
        print(f"  {col}{icon} {mod:4}  {module_status[mod]:15}{R}")
    print()

    # Auto-resolved findings (fixed externally, detected by re-verify)
    if auto_resolved:
        print(f"{G}{B}AUTO-RÉSOLUS ({len(auto_resolved)}) — anciens findings fermés:{R}")
        for f in auto_resolved:
            print(f"  {G}✓ {f.id}  {f.title}{R}")
            print(f"    {GR}{f.file}{R}")
        print()

    # New / reopened
    all_new = sorted(new_findings + reopened, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    if all_new:
        print(f"{B}NOUVEAUX / RÉOUVERTS ({len(all_new)}):{R}")
        for f in all_new:
            col = C.get(f.severity, "")
            tag = "↩ RÉGRESSION" if f in reopened else "NEW"
            print(f"  {col}[{f.severity:8}]{R}  {f.id}  [{tag}]  {f.module}")
            print(f"    {f.title}")
            print(f"    {GR}{f.file}:{f.line if f.line > 0 else '—'}{R}")
            ctx = f.detail.split("\n")[1].strip() if "\n" in f.detail else ""
            if ctx:
                print(f"    {GR}{ctx}{R}")
        print()
    else:
        print(f"  {G}✓ Aucun nouveau finding{R}\n")

    _print_open_summary(state)


# ---------------------------------------------------------------------------
# Post-verify report
# ---------------------------------------------------------------------------

def print_verify_report(
    confirmed: list[Finding],
    resolved: list[Finding],
    finding_id: str | None,
) -> None:
    scope = f"finding {finding_id}" if finding_id else "tous les findings ouverts"
    print(f"\n{B}{_bar('═')}{R}")
    print(f"  {B}OSEye Verify — {scope} — {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}{R}")
    print(f"{B}{_bar('═')}{R}\n")

    if confirmed:
        print(f"{B}CONFIRMÉS ({len(confirmed)}) — toujours présents:{R}")
        for f in sorted(confirmed, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            col = C.get(f.severity, "")
            print(f"  {col}[{f.severity:8}]{R}  {f.id}  {f.title}")
            print(f"    {GR}{f.file}:{f.line if f.line > 0 else '—'}{R}")
        print()

    if resolved:
        print(f"{B}{G}RÉSOLUS ({len(resolved)}) — auto-fermés:{R}")
        for f in resolved:
            print(f"  {G}✓ {f.id}  {f.title}{R}")
            print(f"    {GR}{f.file}{R}")
        print()

    if not confirmed and not resolved:
        print(f"  {GR}Aucun finding open à vérifier.{R}\n")

    print(f"  Confirmés: {len(confirmed)}   Résolus: {len(resolved)}\n")


# ---------------------------------------------------------------------------
# Consolidated report (--report)
# ---------------------------------------------------------------------------

def print_full_report(state: AuditState) -> None:
    open_findings = [f for f in state.findings.values() if f.status == "open"]
    total = len(state.findings)

    print(f"\n{B}{_bar('═')}{R}")
    print(f"  {B}OSEye Rapport consolidé — {datetime.now(UTC).strftime('%Y-%m-%d %H:%M')}{R}")
    print(f"  Dernier scan complet    : {state.last_full_scan or '—'}")
    print(f"  Dernier scan incrémental: {state.last_incremental_scan or '—'}")
    print(f"  Dernière vérification   : {state.last_verify or '—'}")
    print(f"  Findings total (tous statuts): {total}   ouverts: {len(open_findings)}")
    print(f"{B}{_bar('═')}{R}\n")

    if not open_findings:
        print(f"  {G}✓ Aucun finding ouvert.{R}\n")
        return

    for sev in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]:
        items = sorted(
            [f for f in open_findings if f.severity == sev],
            key=lambda f: (f.module, f.file),
        )
        if not items:
            continue
        col = C.get(sev, "")
        print(f"{col}{B}── {sev} ({len(items)}) {_bar('─', 50 - len(sev))}{R}")
        for f in items:
            occ = f"  ×{f.occurrences}" if f.occurrences > 1 else ""
            print(f"  {f.id:10}  {f.module:4}  {f.file}:{f.line if f.line > 0 else '—'}{occ}")
            print(f"    {f.title}")
            print(f"    {GR}pattern:{f.pattern_id}  vu:{f.last_seen[:10]}  first:{f.first_seen[:10]}{R}")
        print()


# ---------------------------------------------------------------------------
# Pattern list (--list-patterns)
# ---------------------------------------------------------------------------

def print_pattern_list(patterns: list[Pattern]) -> None:
    print(f"\n{B}{_bar('═')}{R}")
    print(f"  {B}{len(patterns)} patterns enregistrés{R}")
    print(f"{B}{_bar('═')}{R}\n")

    for cat in ("security", "debug"):
        items = [p for p in patterns if p.category == cat]
        if not items:
            continue
        print(f"{B}── {cat.upper()} ──{R}")
        for p in sorted(items, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            enabled = G + "✓" + R if p.enabled else GR + "✗" + R
            col = C.get(p.severity, "")
            hits = f"hits:{p.hit_count}" if p.hit_count else GR + "jamais déclenché" + R
            fp = f"  {Y}fp:{p.false_positive_count}{R}" if p.false_positive_count else ""
            inverse = f"  {GR}[INVERSE]{R}" if p.is_inverse() else ""
            print(f"  {enabled} {p.id:12} {col}[{p.severity:8}]{R}  {p.name[:42]:42}  {hits}{fp}{inverse}")
        print()


# ---------------------------------------------------------------------------
# Shared summary helper
# ---------------------------------------------------------------------------

def _print_open_summary(state: AuditState) -> None:
    open_f = [f for f in state.findings.values() if f.status == "open"]
    if not open_f:
        print(f"  {G}✓ Aucun finding ouvert{R}\n")
        return

    by_sev: dict[str, list[Finding]] = {}
    for f in open_f:
        by_sev.setdefault(f.severity, []).append(f)

    print(f"{B}FINDINGS OUVERTS (total: {len(open_f)}):{R}")
    for sev in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]:
        if sev in by_sev:
            col = C.get(sev, "")
            print(f"  {col}{sev:8}{R} : {len(by_sev[sev])}")
    print()

    urgent = [f for f in open_f if f.severity in ("BLOCKER", "CRITICAL")]
    if urgent:
        print(f"{B}ACTIONS PRIORITAIRES:{R}")
        for f in sorted(urgent, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
            col = C.get(f.severity, "")
            occ = f"  {Y}×{f.occurrences}{R}" if f.occurrences > 1 else ""
            print(f"  {col}[{f.id}] {f.title}{R}{occ}")
            print(f"    → {GR}{f.file}:{f.line if f.line > 0 else '—'}{R}")
        print()


# ---------------------------------------------------------------------------
# JSON report builder
# ---------------------------------------------------------------------------

def build_json_report(
    state: AuditState,
    new_findings: list[Finding],
    module_status: dict[str, str],
    label: str,
) -> dict:
    open_all = [f for f in state.findings.values() if f.status == "open"]
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "label": label,
        "module_status": module_status,
        "new_findings": [asdict(f) for f in new_findings],
        "all_open_findings": [asdict(f) for f in open_all],
        "stats": {
            "total_open": len(open_all),
            "by_severity": {
                sev: sum(1 for f in open_all if f.severity == sev)
                for sev in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
            },
            "by_module": {
                mod: sum(1 for f in open_all if f.module == mod)
                for mod in sorted({f.module for f in open_all})
            },
        },
    }
