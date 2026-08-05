"""Data models and path constants for the OSEye audit engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).parent.parent.parent.resolve()
TOOLS_DIR = ROOT / "tools"
STATE_FILE = TOOLS_DIR / "audit_state.json"
PATTERNS_FILE = TOOLS_DIR / "audit_patterns.json"
REPORTS_DIR = TOOLS_DIR / "audit_reports"

SEVERITY_ORDER: dict[str, int] = {
    "BLOCKER": 0,
    "CRITICAL": 1,
    "MAJOR": 2,
    "MINOR": 3,
    "INFO": 4,
}

SEVERITY_COLOR: dict[str, str] = {
    "BLOCKER":  "\033[91m",
    "CRITICAL": "\033[93m",
    "MAJOR":    "\033[94m",
    "MINOR":    "\033[96m",
    "INFO":     "\033[90m",
    "RESET":    "\033[0m",
    "GREEN":    "\033[92m",
    "YELLOW":   "\033[93m",
    "GREY":     "\033[90m",
    "BOLD":     "\033[1m",
}

# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str                 # SEC-0001, DBG-0003
    category: str           # "security" | "debug"
    severity: str           # BLOCKER | CRITICAL | MAJOR | MINOR | INFO
    module: str             # M0..M11 | *
    file: str               # repo-relative path
    line: int               # 1-based; -1 if N/A
    pattern_id: str         # which pattern produced this finding
    title: str
    detail: str
    first_seen: str         # ISO datetime
    last_seen: str          # ISO datetime
    occurrences: int = 1
    status: str = "open"    # open | fixed | accepted
    fix_note: str = ""

    def key(self) -> str:
        return f"{self.pattern_id}::{self.file}::{self.line}"


# ---------------------------------------------------------------------------
# Pattern
# ---------------------------------------------------------------------------

@dataclass
class Pattern:
    id: str
    category: str           # "security" | "debug"
    module: str             # target module or "*"
    name: str
    description: str
    severity: str
    targets: list[str]      # glob patterns for target files
    regex: str              # regex to search for (empty → use script)
    script: str             # shell command (empty → use regex)
    enabled: bool = True
    hit_count: int = 0
    false_positive_count: int = 0
    added_date: str = ""
    added_by: str = "init"  # init | user | auto
    notes: str = ""

    def is_inverse(self) -> bool:
        """Inverse patterns fire on ABSENCE of the regex in the target files."""
        return self.id in _INVERSE_PATTERN_IDS


# IDs of patterns that fire when the regex is NOT found.
# Kept here so both scanner and verifier agree on the definition.
_INVERSE_PATTERN_IDS: frozenset[str] = frozenset({
    "SEC-P011",  # trigger immuabilité absent de la migration
    "SEC-P012",  # rate limiting absent sur /auth/token
    "DBG-P002",  # __init__.py manquant
    "DBG-P003",  # code proto non généré
    "DBG-P006",  # interface Go assertion absente
})


# ---------------------------------------------------------------------------
# AuditState
# ---------------------------------------------------------------------------

@dataclass
class AuditState:
    last_full_scan: str = ""
    last_incremental_scan: str = ""
    last_verify: str = ""
    file_hashes: dict[str, str] = field(default_factory=dict)
    findings: dict[str, Finding] = field(default_factory=dict)   # key → Finding
    finding_counter: dict[str, int] = field(default_factory=dict)
    module_status: dict[str, str] = field(default_factory=dict)
    scan_history: list[dict] = field(default_factory=list)
