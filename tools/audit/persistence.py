"""Load and save AuditState and Patterns from disk.

All disk I/O for state and patterns is centralised here.
Nothing else in the package reads or writes these files directly.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from .models import (
    AuditState,
    Finding,
    Pattern,
    PATTERNS_FILE,
    STATE_FILE,
    REPORTS_DIR,
)

# ---------------------------------------------------------------------------
# Default patterns — written to disk on first run
# ---------------------------------------------------------------------------

DEFAULT_PATTERNS: list[dict] = [
    # ── SECURITY ──────────────────────────────────────────────────────────
    {
        "id": "SEC-P001", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "eval() natif Python",
        "description": "eval() Python natif — risque d'injection de code arbitraire",
        "targets": ["server/**/*.py"],
        "regex": r"\beval\s*\(",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Autorisé uniquement via asteval dans rule_engine/evaluator.py",
    },
    {
        "id": "SEC-P002", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "subprocess shell=True",
        "description": "subprocess avec shell=True — injection de commande OS possible",
        "targets": ["server/**/*.py"],
        "regex": r"shell\s*=\s*True",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Autorisé uniquement dans plugin/sandbox.py avec validation du chemin",
    },
    {
        "id": "SEC-P003", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "SQL interpolation f-string",
        "description": "Requête SQL construite avec f-string — injection SQL",
        "targets": ["server/**/*.py"],
        "regex": r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*\{',
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Utiliser SQLAlchemy ORM ou text() avec bindparams",
    },
    {
        "id": "SEC-P004", "category": "security", "module": "M9", "severity": "BLOCKER",
        "name": "JWT algorithme HS256",
        "description": "JWT signé HS256 (symétrique) — doit être RS256",
        "targets": ["server/oseye/api/auth/jwt.py"],
        "regex": r'["\']HS256["\']',
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Algorithme obligatoire : RS256 avec clé privée externe",
    },
    {
        "id": "SEC-P005", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "Secret hardcodé",
        "description": "Clé API, password ou token en dur dans le source",
        "targets": ["server/**/*.py", "agent/**/*.go"],
        "regex": r'(?:api_key|password|secret|token)\s*=\s*["\'][A-Za-z0-9_\-]{12,}["\']',
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Exclure tests et exemples de config",
    },
    {
        "id": "SEC-P006", "category": "security", "module": "M6", "severity": "CRITICAL",
        "name": "agent_id lu depuis payload gRPC",
        "description": "agent_id extrait du payload au lieu du CN du certificat mTLS",
        "targets": ["server/oseye/ingest/grpc_service.py"],
        "regex": r"agent_id.*request\.",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "agent_id doit venir de context.peer_identity() uniquement",
    },
    {
        "id": "SEC-P007", "category": "security", "module": "M8", "severity": "CRITICAL",
        "name": "Import direct backend storage",
        "description": "Composant métier contournant StorageRouter en important directement un backend",
        "targets": ["server/oseye/**/*.py"],
        "regex": r"from oseye\.storage\.backends\.",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Seul StorageRouter instancie les backends",
    },
    {
        "id": "SEC-P008", "category": "security", "module": "*", "severity": "CRITICAL",
        "name": "Clé privée loggée",
        "description": "Clé privée Ed25519 ou JWT dans un appel de log",
        "targets": ["server/**/*.py", "agent/**/*.go"],
        "regex": r'(?:log|print|fmt\.Print|slog\.).*private.*key|private.*key.*(?:log|print)',
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Les clés privées ne doivent jamais apparaître dans les logs",
    },
    {
        "id": "SEC-P009", "category": "security", "module": "M9", "severity": "CRITICAL",
        "name": "CORS wildcard",
        "description": "allow_origins=[\"*\"] — toutes les origines acceptées",
        "targets": ["server/oseye/api/app.py", "server/oseye/config.py"],
        "regex": r'allow_origins\s*=\s*\[.*"\*"',
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Liste explicite d'origines requise",
    },
    {
        "id": "SEC-P010", "category": "security", "module": "M0", "severity": "CRITICAL",
        "name": "Fichiers .pem/.key commités",
        "description": "Certificat ou clé privée dans le dépôt git",
        "targets": [],
        "regex": "",
        "script": "git -C {ROOT} ls-files | grep -E '\\.(pem|key|p12|pfx)$'",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "infra/certs/ doit être dans .gitignore",
    },
    {
        "id": "SEC-P011", "category": "security", "module": "M8", "severity": "CRITICAL",
        "name": "Trigger immuabilité absent (INVERSE)",
        "description": "prevent_decision_update + prevent_custody_update absents de la migration",
        "targets": ["server/oseye/storage/migrations/*.py"],
        "regex": r"prevent_decision_update|prevent_custody",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "PATTERN INVERSÉ : fire si la regex est ABSENTE des fichiers cibles",
    },
    {
        "id": "SEC-P012", "category": "security", "module": "M9", "severity": "MAJOR",
        "name": "Rate limiting absent sur /auth/token (INVERSE)",
        "description": "Pas de rate limiter sur l'endpoint d'authentification",
        "targets": ["server/oseye/api/routers/auth.py", "server/oseye/api/app.py"],
        "regex": r"slowapi|RateLimiter|rate.limit|limiter\.limit",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "PATTERN INVERSÉ : fire si auth.py existe et regex absente",
    },
    # ── DEBUG ─────────────────────────────────────────────────────────────
    {
        "id": "DBG-P001", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "TODO/FIXME non justifié",
        "description": "TODO ou FIXME sans contexte ni ticket",
        "targets": ["server/**/*.py", "agent/**/*.go"],
        "regex": r"#\s*(?:TODO|FIXME|HACK|XXX)(?!\s*\()",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Format attendu : # TODO(ticket-123): description",
    },
    {
        "id": "DBG-P002", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "__init__.py manquant (INVERSE)",
        "description": "Répertoire Python sans __init__.py — ImportError potentiel",
        "targets": [],
        "regex": "",
        "script": "find {ROOT}/server/oseye -type d | while read d; do [ ! -f \"$d/__init__.py\" ] && echo \"$d\"; done",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "PATTERN INVERSÉ via script : chaque ligne de sortie est un finding",
    },
    {
        "id": "DBG-P003", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "Code proto non généré (INVERSE)",
        "description": "agent/gen/ ou server/gen/ absent",
        "targets": [],
        "regex": "",
        "script": "ls {ROOT}/agent/gen/*.go {ROOT}/server/gen/*.py 2>/dev/null | head -1",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "PATTERN INVERSÉ : absence de sortie = finding",
    },
    {
        "id": "DBG-P004", "category": "debug", "module": "*", "severity": "MINOR",
        "name": "print() de debug Python",
        "description": "print() dans le code de production (doit utiliser structlog)",
        "targets": ["server/oseye/**/*.py"],
        "regex": r"^\s*print\s*\(",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Exclure tests et scripts",
    },
    {
        "id": "DBG-P005", "category": "debug", "module": "*", "severity": "MINOR",
        "name": "fmt.Println de debug Go",
        "description": "fmt.Println dans le code de production (doit utiliser slog)",
        "targets": ["agent/**/*.go"],
        "regex": r"fmt\.Println\s*\(",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "",
    },
    {
        "id": "DBG-P006", "category": "debug", "module": "M1", "severity": "CRITICAL",
        "name": "Assertion interface Go absente (INVERSE)",
        "description": "Driver concret sans var _ PlatformDriver = (*Type)(nil)",
        "targets": [
            "agent/internal/platform/linux/driver.go",
            "agent/internal/platform/windows/driver.go",
            "agent/internal/platform/darwin/driver.go",
        ],
        "regex": r"var\s+_\s+(?:collector\.Collector|platform\.PlatformDriver)\s*=",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "PATTERN INVERSÉ : s'applique aux drivers concrets uniquement, pas aux fichiers d'interface",
    },
    {
        "id": "DBG-P007", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "Goroutine sans context Go",
        "description": "go func() sans paramètre — goroutine orpheline, leak au Stop()",
        "targets": ["agent/**/*.go"],
        "regex": r"go func\(\)",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "go func() sans ctx = goroutine non contrôlable",
    },
    {
        "id": "DBG-P008", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "Erreur silencieuse Go",
        "description": "Erreur assignée à _ — perdue sans log ni retour",
        "targets": ["agent/**/*.go"],
        "regex": r",\s*_\s*:?=.*(?:err|error|Err)",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Exclure defer f.Close() — erreur vraiment non-critique",
    },
    {
        "id": "DBG-P009", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "except bare Python",
        "description": "except: sans type — avale toutes les erreurs",
        "targets": ["server/**/*.py"],
        "regex": r"^\s*except\s*:",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Toujours spécifier le type : except ValueError:",
    },
    {
        "id": "DBG-P010", "category": "debug", "module": "M0", "severity": "INFO",
        "name": "Répertoire vide (.gitkeep seul)",
        "description": "Module pas encore implémenté",
        "targets": [],
        "regex": "",
        "script": (
            "find {ROOT}/agent {ROOT}/server -name '.gitkeep' -type f | "
            "while read f; do dir=$(dirname $f); "
            "count=$(ls -A \"$dir\" | grep -v '.gitkeep' | wc -l); "
            "[ \"$count\" -eq 0 ] && echo \"$dir\"; done"
        ),
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Informatif — indique le périmètre non encore implémenté",
    },
]


# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------

def load_state() -> AuditState:
    if not STATE_FILE.exists():
        return AuditState(finding_counter={"SEC": 0, "DBG": 0})
    data = json.loads(STATE_FILE.read_text())
    state = AuditState()
    state.last_full_scan = data.get("last_full_scan", "")
    state.last_incremental_scan = data.get("last_incremental_scan", "")
    state.last_verify = data.get("last_verify", "")
    state.file_hashes = data.get("file_hashes", {})
    state.finding_counter = data.get("finding_counter", {"SEC": 0, "DBG": 0})
    state.module_status = data.get("module_status", {})
    state.scan_history = data.get("scan_history", [])
    for key, fd in data.get("findings", {}).items():
        state.findings[key] = Finding(**fd)
    return state


def save_state(state: AuditState) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "last_full_scan": state.last_full_scan,
        "last_incremental_scan": state.last_incremental_scan,
        "last_verify": state.last_verify,
        "file_hashes": state.file_hashes,
        "finding_counter": state.finding_counter,
        "module_status": state.module_status,
        "scan_history": state.scan_history,
        "findings": {k: asdict(v) for k, v in state.findings.items()},
    }
    STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Patterns persistence
# ---------------------------------------------------------------------------

def load_patterns() -> list[Pattern]:
    if not PATTERNS_FILE.exists():
        patterns = [Pattern(**p) for p in DEFAULT_PATTERNS]
        save_patterns(patterns)
        return patterns
    data = json.loads(PATTERNS_FILE.read_text())
    return [Pattern(**p) for p in data]


def save_patterns(patterns: list[Pattern]) -> None:
    PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
    PATTERNS_FILE.write_text(
        json.dumps([asdict(p) for p in patterns], indent=2, ensure_ascii=False)
    )


# ---------------------------------------------------------------------------
# Report persistence
# ---------------------------------------------------------------------------

def save_report(report: dict, label: str) -> "Path":
    from datetime import datetime
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"audit_{label}_{ts}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return path
