"""Load and save AuditState and Patterns from disk.

All disk I/O for state and patterns is centralised here.
Nothing else in the package reads or writes these files directly.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from .models import (
    PATTERNS_FILE,
    REPORTS_DIR,
    STATE_FILE,
    AuditState,
    Finding,
    Pattern,
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
    # ── SELF-AUDIT : tools/audit/ ─────────────────────────────────────────
    # The audit engine audits itself. These patterns cover the same quality
    # rules as the project code, scoped to tools/audit/*.py
    {
        "id": "TOOL-P001", "category": "debug", "module": "M0", "severity": "BLOCKER",
        "name": "[tools] except bare dans l'engine",
        "description": "except: sans type dans tools/audit/ — masque les erreurs du scanner",
        "targets": ["tools/audit/*.py"],
        "regex": r"^\s*except\s*:",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "BLOCKER dans l'engine : une exception avalée = finding manquant sans avertissement",
    },
    {
        "id": "TOOL-P002", "category": "debug", "module": "M0", "severity": "CRITICAL",
        "name": "[tools] pattern sans targets ni script",
        "description": "Pattern avec targets=[] ET script='' ET pas inversé — ne scanne rien",
        "targets": [],
        "regex": "",
        "script": (
            "python3 -c \""
            "import json, sys; "
            "pats = json.loads(open('{ROOT}/tools/audit_patterns.json').read()); "
            "bad = [p['id'] for p in pats if not p.get('targets') and not p.get('script') "
            "and p['id'] not in {"
            "'SEC-P011','SEC-P012','SEC-P016','SEC-P019','SEC-P020',"
            "'DBG-P002','DBG-P003','DBG-P006','TOOL-P004'}]; "
            "[print(i) for i in bad]\""
        ),
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Un pattern qui ne pointe nulle part n'audite rien — silencieux et trompeur",
    },
    {
        "id": "TOOL-P003", "category": "security", "module": "M0", "severity": "CRITICAL",
        "name": "[tools] shell=True dans scanner sans validation",
        "description": "scan_script() exécute du shell — vérifier qu'aucun input utilisateur n'est injecté",
        "targets": ["tools/audit/scanner.py"],
        "regex": r"shell\s*=\s*True",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Accepté ICI car le script vient de audit_patterns.json, pas d'input utilisateur direct. Vérifier à chaque modification de scan_script().",
    },
    {
        "id": "TOOL-P004", "category": "debug", "module": "M0", "severity": "MAJOR",
        "name": "[tools] DEFAULT_PATTERNS désynchronisé de audit_patterns.json",
        "description": "Un pattern existe dans audit_patterns.json mais pas dans DEFAULT_PATTERNS (ou vice-versa)",
        "targets": [],
        "regex": "",
        "script": (
            "python3 -c \""
            "import json, sys; "
            "pats_file = {p['id'] for p in json.loads(open('{ROOT}/tools/audit_patterns.json').read())}; "
            "import ast, pathlib; "
            "src = pathlib.Path('{ROOT}/tools/audit/persistence.py').read_text(); "
            "tree = ast.parse(src); "
            "ids_in_code = set(); "
            "[ids_in_code.update(v.s for kv in node.keys for v in [kv] if isinstance(v, ast.Constant) and v.s == 'id') "
            " for node in ast.walk(tree)]; "
            "diff = pats_file.symmetric_difference(ids_in_code); "
            "[print(i) for i in sorted(diff)]\""
        ),
        "enabled": False,
        "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "Désactivé par défaut (AST parsing fragile) — activer manuellement pour vérification ponctuelle",
    },
    {
        "id": "TOOL-P005", "category": "debug", "module": "M0", "severity": "MAJOR",
        "name": "[tools] TODO/FIXME non justifié dans l'engine",
        "description": "TODO ou FIXME sans ticket dans tools/audit/",
        "targets": ["tools/audit/*.py", "tools/oseye_audit.py"],
        "regex": r"#\s*(?:TODO|FIXME|HACK|XXX)(?!\s*\()",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "",
    },
    {
        "id": "TOOL-P006", "category": "debug", "module": "M0", "severity": "MAJOR",
        "name": "[tools] print() de debug dans l'engine",
        "description": "print() de debug laissé dans tools/audit/ (hors reporter.py)",
        "targets": ["tools/audit/models.py", "tools/audit/persistence.py",
                    "tools/audit/modules.py", "tools/audit/scanner.py",
                    "tools/audit/verifier.py", "tools/audit/commands.py"],
        "regex": r"^\s*print\s*\(",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "reporter.py et cli.py sont exemptés — c'est leur rôle d'afficher",
    },
    {
        "id": "TOOL-P007", "category": "security", "module": "M0", "severity": "MAJOR",
        "name": "[tools] état audit_state.json commité",
        "description": "audit_state.json ne doit pas être dans le dépôt git",
        "targets": [],
        "regex": "",
        "script": "git -C {ROOT} ls-files tools/audit_state.json",
        "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-05", "added_by": "init",
        "notes": "L'état contient des chemins absolus locaux — ne doit pas être partagé",
    },
    # ── Phase 3–9 : patterns ajoutés 2026-08-10 ──────────────────────────
    {
        "id": "SEC-P013", "category": "security", "module": "M22", "severity": "BLOCKER",
        "name": "eval() dans rule_engine sans sandbox AST",
        "description": "eval() utilisé dans rule_engine sans vérification ast.parse préalable",
        "targets": ["server/oseye/rule_engine/evaluator.py"],
        "regex": r"\beval\s*\(",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "Autorisé SEULEMENT si précédé de ast.parse + compile + builtins={} dans la même fonction. Vérifier evaluator.py:_eval_expr.",
    },
    {
        "id": "SEC-P014", "category": "security", "module": "M31", "severity": "BLOCKER",
        "name": "Plugin path traversal",
        "description": "Chemin de plugin non normalisé — risque de path traversal hors PLUGIN_DIR",
        "targets": ["server/oseye/plugin/manager.py", "server/oseye/plugin/sandbox.py"],
        "regex": r"(?:plugin_path|path).*(?:open|exec|import|load)(?!.*is_relative_to|.*resolve)",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "Tout accès fichier plugin doit utiliser path.resolve().is_relative_to(PLUGIN_DIR).",
    },
    {
        "id": "SEC-P015", "category": "security", "module": "M31", "severity": "CRITICAL",
        "name": "Plugin sans vérification de signature",
        "description": "Chargement de plugin sans appel à PluginVerifier.verify()",
        "targets": ["server/oseye/plugin/manager.py"],
        "regex": r"(?:load|install|enable).*plugin(?!.*verif)|plugin.*(?:load|install)(?!.*verif)",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "Chaque install doit appeler verifier.verify(path, sig_path) avant tout chargement.",
    },
    {
        "id": "SEC-P016", "category": "security", "module": "M28", "severity": "CRITICAL",
        "name": "Decision journal hash non vérifié (INVERSE)",
        "description": "Décision persistée sans vérification de la chaîne de hachage journal",
        "targets": ["server/oseye/decision/journal.py", "server/oseye/decision/engine.py"],
        "regex": r"prev_journal_hash|journal_hash",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "PATTERN INVERSÉ : chercher la PRÉSENCE. Si absents = CRITICAL. Vérifier journal.py:compute_hashes.",
    },
    {
        "id": "SEC-P017", "category": "security", "module": "M9", "severity": "BLOCKER",
        "name": "HS256 en mode production",
        "description": "JWT signé HS256 en dehors d'un contexte test/dev explicite",
        "targets": ["server/oseye/api/auth/jwt.py"],
        "regex": r'_algorithm\s*=\s*["\']HS256["\']',
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "HS256 autorisé uniquement si conditionné sur param 'secret' (mode test). Lire jwt.py:__init__.",
    },
    {
        "id": "SEC-P018", "category": "security", "module": "M32", "severity": "MAJOR",
        "name": "JWT stocké en localStorage (UI)",
        "description": "Token JWT persisté en localStorage — accessible via XSS",
        "targets": ["ui/src/stores/authStore.ts", "ui/src/**/*.ts", "ui/src/**/*.tsx"],
        "regex": r"localStorage\.setItem.*[Tt]oken|localStorage\.setItem.*[Aa]ccess",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "Risque XSS — préférer httpOnly cookie si CSP non configuré. Vérifier app.py pour les security headers.",
    },
    {
        "id": "SEC-P019", "category": "security", "module": "M32", "severity": "MAJOR",
        "name": "Headers de sécurité HTTP absents (INVERSE)",
        "description": "Content-Security-Policy, X-Frame-Options, X-Content-Type-Options absents de l'API",
        "targets": ["server/oseye/api/app.py"],
        "regex": r"Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|SecurityHeadersMiddleware",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "PATTERN INVERSÉ : absence = finding. Important si JWT en localStorage (SEC-P018).",
    },
    {
        "id": "SEC-P020", "category": "security", "module": "M32", "severity": "MAJOR",
        "name": "WebSocket JWT premier frame (INVERSE)",
        "description": "Connexion WebSocket sans envoi du token JWT en premier message",
        "targets": ["ui/src/hooks/useWebSocket.ts"],
        "regex": r"ws\.send.*token|token.*ws\.send",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "PATTERN INVERSÉ : absent = finding. Vérifier useWebSocket.ts:ws.onopen.",
    },
    {
        "id": "DBG-P011", "category": "debug", "module": "*", "severity": "MINOR",
        "name": "TODO/FIXME dans le code UI",
        "description": "TODO ou FIXME sans contexte dans les fichiers TypeScript/TSX",
        "targets": ["ui/src/**/*.ts", "ui/src/**/*.tsx"],
        "regex": r"//\s*(?:TODO|FIXME|HACK|XXX)(?!\s*\()",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "Format attendu : // TODO(ticket): description",
    },
    {
        "id": "DBG-P012", "category": "debug", "module": "M30", "severity": "CRITICAL",
        "name": "asyncio.run() depuis thread gRPC",
        "description": "asyncio.run() dans un worker/service gRPC — RuntimeError event loop already running",
        "targets": ["server/oseye/workers/*.py", "server/oseye/ingest/grpc_service.py"],
        "regex": r"asyncio\.run\s*\(",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "Utiliser asyncio.ensure_future() ou loop.create_task() depuis un thread gRPC.",
    },
    {
        "id": "DBG-P013", "category": "debug", "module": "M25", "severity": "MAJOR",
        "name": "ML score hors intervalle [0, 1]",
        "description": "Score ML retourné sans clamp dans [0.0, 1.0]",
        "targets": ["server/oseye/ml_engine/engine.py", "server/oseye/ml_engine/classifier.py",
                    "server/oseye/ml_engine/anomaly.py"],
        "regex": r"\bscore\b.*return|return.*\bscore\b",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "Vérifier manuellement que chaque retour de score est borné : max(0.0, min(1.0, score)).",
    },
    {
        "id": "DBG-P014", "category": "debug", "module": "M20", "severity": "MAJOR",
        "name": "Goroutine leak dans collectors Go",
        "description": "go func() sans context ni stopCh dans les collectors/watchdog",
        "targets": [
            "agent/internal/platform/linux/**/*.go",
            "agent/internal/watchdog/*.go",
            "agent/internal/mapper/*.go",
        ],
        "regex": r"go func\(\)\s*\{",
        "script": "", "enabled": True, "hit_count": 0, "false_positive_count": 0,
        "added_date": "2026-08-10", "added_by": "phase3-update",
        "notes": "go func() sans paramètre context = goroutine non arrêtable. Vérifier stopCh ou ctx.Done().",
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

def save_report(report: dict, label: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"audit_{label}_{ts}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return path
