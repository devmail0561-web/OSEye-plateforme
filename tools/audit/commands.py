"""Interactive commands: fix, false-positive, add-pattern."""

from __future__ import annotations

from datetime import UTC, datetime

from .models import SEVERITY_ORDER, AuditState, Finding, Pattern
from .persistence import save_patterns, save_state

# ---------------------------------------------------------------------------
# --fix
# ---------------------------------------------------------------------------

def cmd_mark_fixed(state: AuditState, finding_id: str, note: str) -> None:
    finding = _find(state, finding_id)
    if finding is None:
        print(f"  Finding '{finding_id}' introuvable.")
        return
    finding.status = "fixed"
    finding.fix_note = note or f"Marqué fixé le {datetime.now(UTC).isoformat()}"
    save_state(state)
    print(f"  ✓ {finding_id} marqué comme fixé")
    print(f"    Conseil : lancez --verify {finding_id} pour confirmer la correction.")


# ---------------------------------------------------------------------------
# --fp (false positive)
# ---------------------------------------------------------------------------

def cmd_false_positive(
    state: AuditState,
    patterns: list[Pattern],
    finding_id: str,
    note: str = "",
) -> None:
    finding = _find(state, finding_id)
    if finding is None:
        print(f"  Finding '{finding_id}' introuvable.")
        return
    finding.status = "accepted"
    finding.fix_note = note or f"Faux positif accepté le {datetime.now(UTC).isoformat()}"

    for p in patterns:
        if p.id == finding.pattern_id:
            p.false_positive_count += 1
            if p.false_positive_count >= 3:
                print(
                    f"  ⚠  Pattern {p.id} a {p.false_positive_count} faux positifs — "
                    f"envisagez d'affiner sa regex ou de le désactiver dans audit_patterns.json"
                )
            break

    save_state(state)
    save_patterns(patterns)
    print(f"  ✓ {finding_id} marqué comme faux positif")


# ---------------------------------------------------------------------------
# --add-pattern
# ---------------------------------------------------------------------------

def cmd_add_pattern(patterns: list[Pattern]) -> None:
    print("\n── Ajouter un nouveau pattern ──")
    cat_raw = input("Catégorie (security/debug) [security]: ").strip() or "security"
    cat = "security" if "sec" in cat_raw.lower() else "debug"
    prefix = "SEC" if cat == "security" else "DBG"

    existing_nums = [
        int(p.id.split("-P")[1])
        for p in patterns
        if p.id.startswith(f"{prefix}-P") and p.id.split("-P")[1].isdigit()
    ]
    next_num = (max(existing_nums) + 1) if existing_nums else 1
    pid = f"{prefix}-P{next_num:03d}"

    name = input("Nom court du pattern : ").strip()
    if not name:
        print("  Annulé — nom requis.")
        return

    desc = input("Description du risque : ").strip()
    sev = (input("Sévérité (BLOCKER/CRITICAL/MAJOR/MINOR/INFO) [MAJOR]: ").strip() or "MAJOR").upper()
    mod = input("Module cible (* pour tous) [*]: ").strip() or "*"
    targets_raw = input("Fichiers cibles (glob, ex: server/**/*.py), vide=aucun : ").strip()
    targets = [t.strip() for t in targets_raw.split(",")] if targets_raw else []

    regex = input("Regex de détection (vide → utiliser un script) : ").strip()
    script = ""
    if not regex:
        script = input("Commande shell (utiliser {ROOT} pour la racine) : ").strip()

    inverse_raw = input("Pattern inversé — fire si regex ABSENTE ? (o/N) : ").strip().lower()
    notes = input("Notes / quand c'est un faux positif : ").strip()
    if inverse_raw in ("o", "oui", "y", "yes"):
        notes = "PATTERN INVERSÉ : fire si la regex est absente des fichiers cibles. " + notes

    pattern = Pattern(
        id=pid, category=cat, module=mod, name=name, description=desc,
        severity=sev, targets=targets, regex=regex, script=script,
        enabled=True, hit_count=0, false_positive_count=0,
        added_date=datetime.now(UTC).strftime("%Y-%m-%d"),
        added_by="user", notes=notes,
    )
    patterns.append(pattern)
    save_patterns(patterns)
    print(f"\n  ✓ Pattern {pid} ({name}) ajouté dans audit_patterns.json")
    print(f"    Lancez un scan pour le voir en action : python -m tools.audit --mode {cat}")


# ---------------------------------------------------------------------------
# --list-patterns  (logic side — display handled by reporter)
# ---------------------------------------------------------------------------

def get_sorted_patterns(patterns: list[Pattern]) -> list[Pattern]:
    return sorted(patterns, key=lambda p: (p.category, SEVERITY_ORDER.get(p.severity, 9), p.id))


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _find(state: AuditState, finding_id: str) -> Finding | None:
    for f in state.findings.values():
        if f.id == finding_id:
            return f
    return None
