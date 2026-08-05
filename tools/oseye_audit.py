#!/usr/bin/env python3
"""
OSEye Audit Engine — Security & Debug Scanner
============================================
Programme autonome et évolutif d'audit du projet OSEye.

Usage:
    python tools/oseye_audit.py                    # scan complet
    python tools/oseye_audit.py --mode security    # revue sécurité uniquement
    python tools/oseye_audit.py --mode debug       # analyse debug uniquement
    python tools/oseye_audit.py --module M1        # scanner un module précis
    python tools/oseye_audit.py --diff             # scan incrémental (fichiers modifiés seulement)
    python tools/oseye_audit.py --report           # afficher le dernier rapport consolidé
    python tools/oseye_audit.py --add-pattern      # ajouter un pattern manuellement

Architecture:
    - State file   : tools/audit_state.json  (findings accumulés, hashes fichiers, patterns)
    - Patterns     : tools/audit_patterns.json (règles de scan, évolutives)
    - Rapports     : tools/audit_reports/<timestamp>.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Chemins
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent.resolve()
TOOLS_DIR = ROOT / "tools"
STATE_FILE = TOOLS_DIR / "audit_state.json"
PATTERNS_FILE = TOOLS_DIR / "audit_patterns.json"
REPORTS_DIR = TOOLS_DIR / "audit_reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str                      # ex: SEC-001, DBG-003
    category: str                # "security" | "debug"
    severity: str                # "BLOCKER" | "CRITICAL" | "MAJOR" | "MINOR" | "INFO"
    module: str                  # M0, M1, M2 ...
    file: str                    # chemin relatif au repo
    line: int                    # numéro de ligne (-1 si non applicable)
    pattern_id: str              # identifiant du pattern qui l'a trouvé
    title: str
    detail: str
    first_seen: str              # ISO datetime
    last_seen: str               # ISO datetime
    occurrences: int = 1
    status: str = "open"         # "open" | "fixed" | "accepted"
    fix_note: str = ""

    def key(self) -> str:
        return f"{self.pattern_id}::{self.file}::{self.line}"


@dataclass
class Pattern:
    id: str
    category: str                # "security" | "debug"
    module: str                  # module cible ou "*" pour tous
    name: str
    description: str
    severity: str
    targets: list[str]           # globs de fichiers cibles
    regex: str                   # expression régulière de détection (vide = script)
    script: str                  # commande shell (si regex vide)
    enabled: bool = True
    hit_count: int = 0           # combien de fois ce pattern a trouvé qqch
    false_positive_count: int = 0
    added_date: str = ""
    added_by: str = "init"       # "init" | "user" | "auto"
    notes: str = ""


@dataclass
class AuditState:
    last_full_scan: str = ""
    last_incremental_scan: str = ""
    file_hashes: dict[str, str] = field(default_factory=dict)
    findings: dict[str, Finding] = field(default_factory=dict)   # key → Finding
    finding_counter: dict[str, int] = field(default_factory=dict) # "SEC" / "DBG"
    module_status: dict[str, str] = field(default_factory=dict)   # M0 → "implemented" | "partial" | "absent"
    scan_history: list[dict] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Patterns par défaut (bootstrap)
# ---------------------------------------------------------------------------

DEFAULT_PATTERNS: list[dict] = [
    # ===== SECURITY PATTERNS =====
    {
        "id": "SEC-P001", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "eval() natif Python",
        "description": "Utilisation de eval() Python natif — risque d'injection de code",
        "targets": ["server/**/*.py"],
        "regex": r"\beval\s*\(",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Autoriser uniquement asteval dans rule_engine/evaluator.py",
    },
    {
        "id": "SEC-P002", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "shell=True subprocess",
        "description": "subprocess.run/Popen avec shell=True — risque d'injection de commande",
        "targets": ["server/**/*.py"],
        "regex": r"shell\s*=\s*True",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Autorisé uniquement dans plugin/sandbox.py avec validation du path",
    },
    {
        "id": "SEC-P003", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "SQL interpolation f-string",
        "description": "Requête SQL construite avec f-string — injection SQL",
        "targets": ["server/**/*.py"],
        "regex": r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*\{',
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Toujours utiliser SQLAlchemy ORM ou text() avec bindparams",
    },
    {
        "id": "SEC-P004", "category": "security", "module": "M9", "severity": "BLOCKER",
        "name": "Algorithme JWT HS256",
        "description": "JWT signé avec HS256 (symétrique) — doit être RS256",
        "targets": ["server/oseye/api/auth/jwt.py"],
        "regex": r'["\']HS256["\']',
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Algorithme obligatoire : RS256 avec clé privée externe",
    },
    {
        "id": "SEC-P005", "category": "security", "module": "*", "severity": "BLOCKER",
        "name": "Secret en dur dans le code",
        "description": "Clé API, mot de passe ou token hardcodé dans le source",
        "targets": ["server/**/*.py", "agent/**/*.go"],
        "regex": r'(?:api_key|password|secret|token)\s*=\s*["\'][A-Za-z0-9_\-]{12,}["\']',
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Exclure les tests et les exemples de config",
    },
    {
        "id": "SEC-P006", "category": "security", "module": "M6", "severity": "CRITICAL",
        "name": "agent_id lu depuis le payload gRPC",
        "description": "agent_id extrait du payload au lieu du CN du certificat mTLS",
        "targets": ["server/oseye/ingest/grpc_service.py"],
        "regex": r"agent_id.*request\.",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "agent_id doit toujours venir de context.peer_identity() (CN certificat mTLS)",
    },
    {
        "id": "SEC-P007", "category": "security", "module": "M8", "severity": "CRITICAL",
        "name": "Import direct de backend storage",
        "description": "Composant métier important directement un backend (contourne StorageRouter)",
        "targets": ["server/oseye/**/*.py"],
        "regex": r"from oseye\.storage\.backends\.",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Seul StorageRouter doit instancier les backends",
    },
    {
        "id": "SEC-P008", "category": "security", "module": "*", "severity": "CRITICAL",
        "name": "Clé privée loggée",
        "description": "Clé privée Ed25519 ou JWT passée dans un appel de log",
        "targets": ["server/**/*.py", "agent/**/*.go"],
        "regex": r'(?:log|print|fmt\.Print|slog\.).*private.*key|private.*key.*(?:log|print)',
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Les clés privées ne doivent jamais apparaître dans les logs",
    },
    {
        "id": "SEC-P009", "category": "security", "module": "M9", "severity": "CRITICAL",
        "name": "CORS wildcard",
        "description": "allow_origins=[\"*\"] — accepte toutes les origines",
        "targets": ["server/oseye/api/app.py", "server/oseye/config.py"],
        "regex": r'allow_origins.*\*|origins.*=.*\[\s*["\'\*]',
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Liste explicite d'origines requise, jamais wildcard",
    },
    {
        "id": "SEC-P010", "category": "security", "module": "M0", "severity": "CRITICAL",
        "name": "Fichiers .pem ou .key commités",
        "description": "Certificat ou clé privée présent dans le dépôt git",
        "targets": [],
        "regex": "",
        "script": "git -C {ROOT} ls-files | grep -E '\\.(pem|key|p12|pfx)$'",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "infra/certs/ doit être dans .gitignore",
    },
    {
        "id": "SEC-P011", "category": "security", "module": "M8", "severity": "CRITICAL",
        "name": "Trigger immuabilité absent de la migration",
        "description": "Les triggers prevent_decision_update et prevent_custody_update doivent être dans V001",
        "targets": ["server/oseye/storage/migrations/*.py"],
        "regex": r"prevent_decision_update|prevent_custody",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Absence = findings inversé : chercher le fichier ET l'absence du pattern",
    },
    {
        "id": "SEC-P012", "category": "security", "module": "M9", "severity": "MAJOR",
        "name": "Rate limiting absent sur /auth/token",
        "description": "Pas de rate limiter sur l'endpoint d'authentification",
        "targets": ["server/oseye/api/routers/auth.py", "server/oseye/api/app.py"],
        "regex": r"slowapi|RateLimiter|rate.limit|limiter\.limit",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Absence = findings inversé : si /auth/token existe et pas de rate limit",
    },
    # ===== DEBUG PATTERNS =====
    {
        "id": "DBG-P001", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "TODO / FIXME non justifié",
        "description": "TODO ou FIXME sans contexte ni ticket",
        "targets": ["server/**/*.py", "agent/**/*.go"],
        "regex": r"#\s*(?:TODO|FIXME|HACK|XXX)(?!\s*\()",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Format attendu : # TODO(ticket-123): description",
    },
    {
        "id": "DBG-P002", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "__init__.py manquant dans package Python",
        "description": "Répertoire Python sans __init__.py — ImportError potentiel",
        "targets": [],
        "regex": "",
        "script": "find {ROOT}/server/oseye -type d | while read d; do [ ! -f \"$d/__init__.py\" ] && echo \"$d\"; done",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "",
    },
    {
        "id": "DBG-P003", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "Code proto non généré",
        "description": "gen/ absent — scripts/generate_proto.sh n'a pas été lancé",
        "targets": [],
        "regex": "",
        "script": "ls {ROOT}/agent/gen/*.go {ROOT}/server/gen/*.py 2>/dev/null | head -3",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Absence de fichiers = finding",
    },
    {
        "id": "DBG-P004", "category": "debug", "module": "*", "severity": "MINOR",
        "name": "print() de debug dans le code Python",
        "description": "print() laissé dans le code de production (doit utiliser structlog)",
        "targets": ["server/oseye/**/*.py"],
        "regex": r"^\s*print\s*\(",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Exclure les tests et scripts",
    },
    {
        "id": "DBG-P005", "category": "debug", "module": "*", "severity": "MINOR",
        "name": "fmt.Println de debug dans le code Go",
        "description": "fmt.Println laissé dans le code de production (doit utiliser slog)",
        "targets": ["agent/**/*.go"],
        "regex": r"fmt\.Println\s*\(",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "",
    },
    {
        "id": "DBG-P006", "category": "debug", "module": "M1", "severity": "CRITICAL",
        "name": "Interface Go non satisfaite (assertion absente)",
        "description": "Implémentation de Collector ou PlatformDriver sans assertion var _ Interface = (*Type)(nil)",
        "targets": ["agent/internal/platform/**/*.go", "agent/internal/collector/**/*.go"],
        "regex": r"var\s+_\s+(?:collector\.Collector|platform\.PlatformDriver)\s*=",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Absence = finding inversé : si fichier implémente l'interface sans l'assertion",
    },
    {
        "id": "DBG-P007", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "Goroutine sans context propagé",
        "description": "go func() lancée sans ctx context.Context — ne peut pas être arrêtée proprement",
        "targets": ["agent/**/*.go"],
        "regex": r"go func\(\)",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "go func() sans paramètre = goroutine orpheline, risque de goroutine leak",
    },
    {
        "id": "DBG-P008", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "Gestion d'erreur silencieuse Go",
        "description": "Erreur assignée à _ sans log ni retour",
        "targets": ["agent/**/*.go"],
        "regex": r",\s*_\s*:?=.*(?:err|error|Err)",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Exclure les cas où l'erreur est vraiment non-critique (ex: defer f.Close())",
    },
    {
        "id": "DBG-P009", "category": "debug", "module": "*", "severity": "MAJOR",
        "name": "except bare Python",
        "description": "except: sans type d'exception — avale toutes les erreurs",
        "targets": ["server/**/*.py"],
        "regex": r"^\s*except\s*:",
        "script": "",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Toujours spécifier le type d'exception : except ValueError: etc.",
    },
    {
        "id": "DBG-P010", "category": "debug", "module": "M0", "severity": "INFO",
        "name": "Répertoires vides (.gitkeep uniquement)",
        "description": "Répertoire ne contenant que .gitkeep — module pas encore implémenté",
        "targets": [],
        "regex": "",
        "script": "find {ROOT}/agent {ROOT}/server -name '.gitkeep' -type f | while read f; do dir=$(dirname $f); count=$(ls -A \"$dir\" | grep -v '.gitkeep' | wc -l); [ \"$count\" -eq 0 ] && echo \"$dir\"; done",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Informatif uniquement — indique le périmètre non encore implémenté",
    },
]

# ---------------------------------------------------------------------------
# Gestion de l'état persistant
# ---------------------------------------------------------------------------

def load_state() -> AuditState:
    if STATE_FILE.exists():
        data = json.loads(STATE_FILE.read_text())
        state = AuditState()
        state.last_full_scan = data.get("last_full_scan", "")
        state.last_incremental_scan = data.get("last_incremental_scan", "")
        state.file_hashes = data.get("file_hashes", {})
        state.finding_counter = data.get("finding_counter", {"SEC": 0, "DBG": 0})
        state.module_status = data.get("module_status", {})
        state.scan_history = data.get("scan_history", [])
        # Reconstituer les findings
        for key, fd in data.get("findings", {}).items():
            state.findings[key] = Finding(**fd)
        return state
    return AuditState(finding_counter={"SEC": 0, "DBG": 0})


def save_state(state: AuditState) -> None:
    data = {
        "last_full_scan": state.last_full_scan,
        "last_incremental_scan": state.last_incremental_scan,
        "file_hashes": state.file_hashes,
        "finding_counter": state.finding_counter,
        "module_status": state.module_status,
        "scan_history": state.scan_history,
        "findings": {k: asdict(v) for k, v in state.findings.items()},
    }
    STATE_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def load_patterns() -> list[Pattern]:
    if PATTERNS_FILE.exists():
        data = json.loads(PATTERNS_FILE.read_text())
        return [Pattern(**p) for p in data]
    # Bootstrap
    patterns = [Pattern(**p) for p in DEFAULT_PATTERNS]
    save_patterns(patterns)
    return patterns


def save_patterns(patterns: list[Pattern]) -> None:
    PATTERNS_FILE.write_text(
        json.dumps([asdict(p) for p in patterns], indent=2, ensure_ascii=False)
    )

# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except Exception:
        return ""


def resolve_globs(patterns_globs: list[str]) -> list[Path]:
    """Résoudre les globs de fichiers cibles."""
    files: list[Path] = []
    for g in patterns_globs:
        files.extend(ROOT.glob(g))
    return [f for f in files if f.is_file() and not any(
        part in f.parts for part in ("__pycache__", ".git", "gen", "node_modules")
    )]


def detect_modules() -> dict[str, str]:
    """Déterminer quels modules sont implémentés."""
    module_files = {
        "M0": ["proto/event.proto", "server/oseye/core/schema.py", "agent/internal/platform/interface.go"],
        "M1": ["agent/internal/chain/hasher.go", "agent/internal/signer/ed25519.go", "agent/internal/buffer/sqlite_buffer.go"],
        "M2": ["agent/internal/platform/linux/driver.go", "agent/internal/platform/linux/ebpf/loader.go"],
        "M3": ["agent/internal/transport/grpc_client.go"],
        "M4": ["agent/cmd/oseye-agent/main.go"],
        "M5": ["server/oseye/bus/memory.py", "server/oseye/bus/redis_streams.py"],
        "M6": ["server/oseye/ingest/grpc_service.py", "server/oseye/ingest/validator.py"],
        "M7": ["server/oseye/normalizer/engine.py"],
        "M8": ["server/oseye/storage/backends/sqlite.py", "server/oseye/storage/repositories/event_repo.py"],
        "M9": ["server/oseye/api/auth/jwt.py", "server/oseye/api/routers/events.py"],
        "M10": ["server/oseye/workers/storage_writer.py", "server/oseye/core/runner.py"],
        "M11": ["infra/docker/docker-compose.dev.yml", ".github/workflows/ci.yml"],
    }
    status: dict[str, str] = {}
    for mod, files in module_files.items():
        existing = sum(1 for f in files if (ROOT / f).exists() and (ROOT / f).stat().st_size > 50)
        if existing == 0:
            status[mod] = "absent"
        elif existing < len(files):
            status[mod] = "partial"
        else:
            status[mod] = "implemented"
    return status


def get_changed_files(state: AuditState) -> list[Path]:
    """Retourner les fichiers qui ont changé depuis le dernier scan."""
    changed: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(p in path.parts for p in (".git", "__pycache__", "node_modules", "gen", "audit_reports")):
            continue
        if path.suffix not in (".py", ".go", ".proto", ".yaml", ".yml", ".toml", ".json", ".c", ".h"):
            continue
        rel = str(path.relative_to(ROOT))
        current_hash = file_hash(path)
        if state.file_hashes.get(rel) != current_hash:
            changed.append(path)
    return changed


def update_file_hashes(state: AuditState, files: list[Path]) -> None:
    for path in files:
        rel = str(path.relative_to(ROOT))
        state.file_hashes[rel] = file_hash(path)


def next_finding_id(state: AuditState, category: str) -> str:
    prefix = "SEC" if category == "security" else "DBG"
    state.finding_counter[prefix] = state.finding_counter.get(prefix, 0) + 1
    return f"{prefix}-{state.finding_counter[prefix]:04d}"

# ---------------------------------------------------------------------------
# Moteur de scan
# ---------------------------------------------------------------------------

def scan_regex_pattern(pattern: Pattern, files: list[Path] | None = None) -> list[tuple[Path, int, str]]:
    """Appliquer un pattern regex sur les fichiers cibles. Retourne (fichier, ligne, texte)."""
    if not pattern.regex:
        return []
    targets = files if files is not None else resolve_globs(pattern.targets)
    if not targets:
        return []
    rx = re.compile(pattern.regex, re.IGNORECASE)
    results: list[tuple[Path, int, str]] = []
    for fpath in targets:
        try:
            for i, line in enumerate(fpath.read_text(errors="ignore").splitlines(), 1):
                if rx.search(line):
                    results.append((fpath, i, line.strip()))
        except Exception:
            pass
    return results


def scan_script_pattern(pattern: Pattern) -> list[tuple[str, int, str]]:
    """Exécuter un script shell et retourner les lignes de sortie comme findings."""
    if not pattern.script:
        return []
    cmd = pattern.script.replace("{ROOT}", str(ROOT))
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30, cwd=ROOT
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return [(l, -1, l) for l in lines]
    except Exception:
        return []


def is_inverse_pattern(pattern: Pattern) -> bool:
    """Patterns inversés : ils signalent une ABSENCE (ex: trigger non présent)."""
    return pattern.id in {"SEC-P011", "SEC-P012", "DBG-P002", "DBG-P003", "DBG-P006"}


def apply_inverse_pattern(pattern: Pattern, state: AuditState) -> list[tuple[str, int, str]]:
    """Pour les patterns inversés, chercher l'absence du motif dans les fichiers cibles."""
    targets = resolve_globs(pattern.targets)
    if not targets:
        return []
    rx = re.compile(pattern.regex, re.IGNORECASE)
    findings = []
    for fpath in targets:
        try:
            content = fpath.read_text(errors="ignore")
            if not rx.search(content):
                findings.append((str(fpath.relative_to(ROOT)), -1,
                                 f"Pattern '{pattern.regex}' absent de {fpath.name}"))
        except Exception:
            pass
    return findings


def run_scan(
    state: AuditState,
    patterns: list[Pattern],
    mode: str = "all",
    module_filter: str | None = None,
    incremental: bool = False,
) -> list[Finding]:
    """Cœur du scanner. Retourne les nouveaux findings."""

    now = datetime.now().isoformat()
    new_findings: list[Finding] = []

    # Fichiers à scanner
    if incremental:
        changed_files = get_changed_files(state)
        print(f"  Scan incrémental — {len(changed_files)} fichiers modifiés")
    else:
        changed_files = None  # scan complet

    active_patterns = [
        p for p in patterns
        if p.enabled
        and (mode == "all" or p.category == mode)
        and (module_filter is None or p.module in (module_filter, "*"))
    ]

    print(f"  {len(active_patterns)} patterns actifs")

    for pattern in active_patterns:
        raw_results: list[tuple[Any, int, str]] = []

        if is_inverse_pattern(pattern):
            raw_results = apply_inverse_pattern(pattern, state)
        elif pattern.script:
            raw_results = scan_script_pattern(pattern)
        elif pattern.regex:
            # Filtrer les fichiers si scan incrémental
            if incremental and changed_files is not None:
                targets = [f for f in resolve_globs(pattern.targets) if f in changed_files]
            else:
                targets = resolve_globs(pattern.targets)
            raw_results = scan_regex_pattern(pattern, targets)

        if not raw_results:
            continue

        pattern.hit_count += 1

        for file_or_str, line_num, text in raw_results:
            if isinstance(file_or_str, Path):
                rel_file = str(file_or_str.relative_to(ROOT))
            else:
                rel_file = str(file_or_str)

            # Déduplication : même pattern + même fichier + même ligne
            key = f"{pattern.id}::{rel_file}::{line_num}"

            if key in state.findings:
                # Mise à jour du finding existant
                existing = state.findings[key]
                existing.last_seen = now
                existing.occurrences += 1
                if existing.status == "fixed":
                    # Réouverture — la correction n'a pas tenu
                    existing.status = "open"
                    existing.fix_note = f"Réouvert le {now}"
                    new_findings.append(existing)
            else:
                # Nouveau finding
                fid = next_finding_id(state, pattern.category)
                finding = Finding(
                    id=fid,
                    category=pattern.category,
                    severity=pattern.severity,
                    module=pattern.module,
                    file=rel_file,
                    line=line_num,
                    pattern_id=pattern.id,
                    title=pattern.name,
                    detail=f"{pattern.description}\n  Contexte: {text[:200]}",
                    first_seen=now,
                    last_seen=now,
                )
                state.findings[key] = finding
                new_findings.append(finding)

    return new_findings


# ---------------------------------------------------------------------------
# Vérification des findings précédents (fermés → rouverts si détectés à nouveau)
# ---------------------------------------------------------------------------

def verify_fixed_findings(state: AuditState, patterns: list[Pattern]) -> list[Finding]:
    """Rescanner les findings marqués 'fixed' pour détecter les régressions."""
    reopened: list[Finding] = []
    pattern_map = {p.id: p for p in patterns}

    for key, finding in state.findings.items():
        if finding.status != "fixed":
            continue
        pat = pattern_map.get(finding.pattern_id)
        if not pat or not pat.enabled:
            continue
        # Rescanner uniquement ce fichier pour ce pattern
        fpath = ROOT / finding.file
        if not fpath.exists():
            continue
        results = scan_regex_pattern(pat, [fpath])
        if results:
            finding.status = "open"
            finding.last_seen = datetime.now().isoformat()
            finding.occurrences += 1
            finding.fix_note = f"Régression détectée le {finding.last_seen}"
            reopened.append(finding)

    return reopened

# ---------------------------------------------------------------------------
# Rapport
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}
SEVERITY_COLOR = {
    "BLOCKER":  "\033[91m",   # rouge vif
    "CRITICAL": "\033[93m",   # jaune
    "MAJOR":    "\033[94m",   # bleu
    "MINOR":    "\033[96m",   # cyan
    "INFO":     "\033[90m",   # gris
    "RESET":    "\033[0m",
}


def print_report(
    state: AuditState,
    new_findings: list[Finding],
    reopened: list[Finding],
    module_status: dict[str, str],
) -> None:
    C = SEVERITY_COLOR
    R = C["RESET"]

    print(f"\n{'='*70}")
    print(f"  OSEye Audit Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*70}\n")

    # Modules
    print("MODULES DÉTECTÉS:")
    for mod, status in sorted(module_status.items()):
        icon = {"implemented": "✓", "partial": "~", "absent": "○"}.get(status, "?")
        color = {"implemented": "\033[92m", "partial": "\033[93m", "absent": "\033[90m"}.get(status, "")
        print(f"  {color}{icon} {mod:4} {status:15}{R}")
    print()

    # Nouveaux findings
    if new_findings or reopened:
        all_new = sorted(new_findings + reopened, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        print(f"NOUVEAUX / RÉOUVERTS ({len(all_new)}):")
        for f in all_new:
            col = C.get(f.severity, "")
            marker = "↩ RÉGRESSION" if f in reopened else "NEW"
            print(f"  {col}[{f.severity:8}]{R} {f.id} [{marker}] {f.module}")
            print(f"           {f.title}")
            print(f"           {f.file}:{f.line if f.line > 0 else '—'}")
            if "\n" in f.detail:
                print(f"           {f.detail.split(chr(10))[1].strip()}")
            print()
    else:
        print("  ✓ Aucun nouveau finding\n")

    # Résumé global des findings ouverts
    open_findings = [f for f in state.findings.values() if f.status == "open"]
    if open_findings:
        by_severity: dict[str, list[Finding]] = {}
        for f in open_findings:
            by_severity.setdefault(f.severity, []).append(f)

        print(f"FINDINGS OUVERTS (total: {len(open_findings)}):")
        for sev in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]:
            items = by_severity.get(sev, [])
            if items:
                col = C.get(sev, "")
                print(f"  {col}{sev:8}{R} : {len(items)}")
        print()

        # Détail des BLOCKER et CRITICAL
        urgent = [f for f in open_findings if f.severity in ("BLOCKER", "CRITICAL")]
        if urgent:
            print("ACTIONS PRIORITAIRES:")
            for f in sorted(urgent, key=lambda x: SEVERITY_ORDER.get(x.severity, 9)):
                col = C.get(f.severity, "")
                print(f"  {col}[{f.id}] {f.title}{R}")
                print(f"    → {f.file}:{f.line if f.line > 0 else '—'}")
                if f.occurrences > 1:
                    print(f"    ⚠  Vu {f.occurrences}x (première fois: {f.first_seen[:10]})")
            print()

    else:
        print("  ✓ Aucun finding ouvert\n")

    print(f"{'='*70}")
    print(f"  State : {STATE_FILE}")
    print(f"  Patterns : {PATTERNS_FILE}")
    print(f"{'='*70}\n")


def save_report(
    state: AuditState,
    new_findings: list[Finding],
    module_status: dict[str, str],
    mode: str,
) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = REPORTS_DIR / f"audit_{mode}_{ts}.json"
    report = {
        "generated_at": datetime.now().isoformat(),
        "mode": mode,
        "module_status": module_status,
        "new_findings": [asdict(f) for f in new_findings],
        "all_open_findings": [asdict(f) for f in state.findings.values() if f.status == "open"],
        "stats": {
            "total_open": sum(1 for f in state.findings.values() if f.status == "open"),
            "by_severity": {
                sev: sum(1 for f in state.findings.values() if f.status == "open" and f.severity == sev)
                for sev in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
            },
        },
    }
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return report_path


# ---------------------------------------------------------------------------
# Commandes interactives
# ---------------------------------------------------------------------------

def cmd_show_report(state: AuditState) -> None:
    """Afficher le rapport consolidé depuis l'état persistant."""
    open_findings = sorted(
        [f for f in state.findings.values() if f.status == "open"],
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.module, f.file),
    )
    print(f"\n{'='*70}")
    print(f"  OSEye — Rapport consolidé — {len(open_findings)} findings ouverts")
    print(f"  Dernier scan complet : {state.last_full_scan or 'jamais'}")
    print(f"  Dernier scan incrémental : {state.last_incremental_scan or 'jamais'}")
    print(f"{'='*70}\n")

    for sev in ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]:
        items = [f for f in open_findings if f.severity == sev]
        if not items:
            continue
        col = SEVERITY_COLOR.get(sev, "")
        R = SEVERITY_COLOR["RESET"]
        print(f"{col}── {sev} ({len(items)}) {'─'*(50-len(sev))}{R}")
        for f in items:
            print(f"  {f.id}  {f.module:4}  {f.file}:{f.line if f.line > 0 else '—'}")
            print(f"       {f.title}")
            print(f"       Pattern: {f.pattern_id}  |  Occurrences: {f.occurrences}  |  Vu: {f.last_seen[:10]}")
        print()


def cmd_mark_fixed(state: AuditState, finding_id: str, note: str) -> None:
    """Marquer un finding comme corrigé."""
    for key, f in state.findings.items():
        if f.id == finding_id:
            f.status = "fixed"
            f.fix_note = note or f"Marqué fixé le {datetime.now().isoformat()}"
            save_state(state)
            print(f"  ✓ {finding_id} marqué comme fixé")
            return
    print(f"  Finding {finding_id} introuvable")


def cmd_add_pattern(patterns: list[Pattern]) -> None:
    """Ajouter un nouveau pattern interactivement."""
    print("\n── Ajouter un nouveau pattern ──")
    pid_prefix = input("Catégorie (security/debug) [security]: ").strip() or "security"
    cat = "security" if "sec" in pid_prefix.lower() else "debug"
    prefix = "SEC" if cat == "security" else "DBG"
    existing_ids = [p.id for p in patterns if p.id.startswith(f"{prefix}-P")]
    nums = [int(p.split("-P")[1]) for p in existing_ids if "-P" in p]
    next_num = (max(nums) + 1) if nums else 1
    pid = f"{prefix}-P{next_num:03d}"

    name = input(f"Nom du pattern: ").strip()
    desc = input("Description: ").strip()
    sev = input("Sévérité (BLOCKER/CRITICAL/MAJOR/MINOR/INFO) [MAJOR]: ").strip() or "MAJOR"
    mod = input("Module cible (* pour tous) [*]: ").strip() or "*"
    targets = input("Fichiers cibles (glob, ex: server/**/*.py) []: ").strip()
    regex = input("Regex de détection (vide pour script): ").strip()
    script = ""
    if not regex:
        script = input("Commande shell (utiliser {ROOT} pour la racine): ").strip()
    notes = input("Notes: ").strip()

    pattern = Pattern(
        id=pid, category=cat, module=mod, name=name, description=desc,
        severity=sev.upper(), targets=[targets] if targets else [],
        regex=regex, script=script, enabled=True, hit_count=0,
        false_positive_count=0, added_date=datetime.now().strftime("%Y-%m-%d"),
        added_by="user", notes=notes,
    )
    patterns.append(pattern)
    save_patterns(patterns)
    print(f"  ✓ Pattern {pid} ajouté et sauvegardé dans {PATTERNS_FILE}")


def cmd_false_positive(state: AuditState, patterns: list[Pattern], finding_id: str) -> None:
    """Marquer un finding comme faux positif et incrémenter le compteur du pattern."""
    for key, f in state.findings.items():
        if f.id == finding_id:
            f.status = "accepted"
            f.fix_note = f"Faux positif accepté le {datetime.now().isoformat()}"
            # Incrémenter le compteur de faux positifs du pattern
            for p in patterns:
                if p.id == f.pattern_id:
                    p.false_positive_count += 1
                    if p.false_positive_count >= 3:
                        print(f"  ⚠  Pattern {p.id} a {p.false_positive_count} faux positifs — envisager de le désactiver")
            save_state(state)
            save_patterns(patterns)
            print(f"  ✓ {finding_id} marqué comme faux positif")
            return
    print(f"  Finding {finding_id} introuvable")


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="OSEye Audit Engine — Security & Debug Scanner"
    )
    parser.add_argument("--mode", choices=["all", "security", "debug"], default="all")
    parser.add_argument("--module", help="Scanner un module précis (ex: M1)")
    parser.add_argument("--diff", action="store_true", help="Scan incrémental (fichiers modifiés)")
    parser.add_argument("--report", action="store_true", help="Afficher le rapport consolidé")
    parser.add_argument("--add-pattern", action="store_true", help="Ajouter un pattern interactivement")
    parser.add_argument("--fix", metavar="ID", help="Marquer un finding comme corrigé")
    parser.add_argument("--fp", metavar="ID", help="Marquer un finding comme faux positif")
    parser.add_argument("--note", default="", help="Note associée à --fix")
    parser.add_argument("--list-patterns", action="store_true", help="Lister tous les patterns")
    args = parser.parse_args()

    state = load_state()
    patterns = load_patterns()

    # Commandes non-scan
    if args.report:
        cmd_show_report(state)
        return 0

    if args.add_pattern:
        cmd_add_pattern(patterns)
        return 0

    if args.fix:
        cmd_mark_fixed(state, args.fix, args.note)
        return 0

    if args.fp:
        cmd_false_positive(state, patterns, args.fp)
        return 0

    if args.list_patterns:
        print(f"\n{'='*60}")
        print(f"  {len(patterns)} patterns enregistrés")
        print(f"{'='*60}")
        for p in sorted(patterns, key=lambda x: (x.category, x.severity)):
            status = "✓" if p.enabled else "✗"
            hits = f"hits:{p.hit_count}" if p.hit_count else "jamais déclenché"
            print(f"  {status} {p.id:12} [{p.severity:8}] {p.name[:40]:40} ({hits})")
        return 0

    # ── Scan ──────────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  OSEye Audit Engine — mode={args.mode}{' diff' if args.diff else ''}{' module='+args.module if args.module else ''}")
    print(f"{'='*70}\n")

    # Détecter les modules implémentés
    print("Détection des modules...")
    module_status = detect_modules()
    state.module_status = module_status

    # Vérifier les régressions sur les findings fixés
    print("Vérification des régressions...")
    reopened = verify_fixed_findings(state, patterns)
    if reopened:
        print(f"  ⚠  {len(reopened)} finding(s) réouverts (régression)")

    # Scan principal
    print(f"Scan {'incrémental' if args.diff else 'complet'}...")
    new_findings = run_scan(
        state=state,
        patterns=patterns,
        mode=args.mode,
        module_filter=args.module,
        incremental=args.diff,
    )

    # Mettre à jour les hashes
    all_files = list(ROOT.rglob("*"))
    src_files = [
        f for f in all_files if f.is_file() and f.suffix in
        (".py", ".go", ".proto", ".yaml", ".yml", ".toml", ".c", ".h")
        and not any(p in f.parts for p in (".git", "__pycache__", "node_modules"))
    ]
    update_file_hashes(state, src_files)

    # Timestamps
    now = datetime.now().isoformat()
    if args.diff:
        state.last_incremental_scan = now
    else:
        state.last_full_scan = now

    # Historique
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

    # Sauvegarder
    save_state(state)
    save_patterns(patterns)

    # Rapport
    print_report(state, new_findings, reopened, module_status)
    report_path = save_report(state, new_findings, module_status, args.mode)
    print(f"  Rapport JSON : {report_path}\n")

    # Code de retour : non-zero si des BLOCKERs ouverts
    blockers = sum(
        1 for f in state.findings.values()
        if f.status == "open" and f.severity == "BLOCKER"
    )
    return 1 if blockers > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
