"""Filesystem utilities: file hashing, glob resolution, module detection."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .models import ROOT, AuditState

# Suffixes considered as source files for change tracking
_SOURCE_SUFFIXES = frozenset({
    ".py", ".go", ".proto", ".yaml", ".yml", ".toml", ".json", ".c", ".h",
})

# Directories to always ignore
_IGNORE_DIRS = frozenset({
    ".git", "__pycache__", "node_modules", "gen", "audit_reports", ".venv",
})


def file_hash(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


def resolve_globs(globs: list[str]) -> list[Path]:
    """Resolve glob patterns relative to ROOT, excluding noise directories."""
    files: list[Path] = []
    for g in globs:
        for f in ROOT.glob(g):
            if f.is_file() and not any(p in _IGNORE_DIRS for p in f.parts):
                files.append(f)
    return files


def all_source_files() -> list[Path]:
    result: list[Path] = []
    for f in ROOT.rglob("*"):
        if not f.is_file():
            continue
        if any(p in _IGNORE_DIRS for p in f.parts):
            continue
        if f.suffix in _SOURCE_SUFFIXES:
            result.append(f)
    return result


def get_changed_files(state: AuditState) -> list[Path]:
    """Return source files whose hash differs from the stored value."""
    changed: list[Path] = []
    for path in all_source_files():
        rel = str(path.relative_to(ROOT))
        if state.file_hashes.get(rel) != file_hash(path):
            changed.append(path)
    return changed


def update_file_hashes(state: AuditState, files: list[Path]) -> None:
    for path in files:
        rel = str(path.relative_to(ROOT))
        state.file_hashes[rel] = file_hash(path)


# ---------------------------------------------------------------------------
# Module detection
# ---------------------------------------------------------------------------

# For each module: list of files that must exist and be non-trivial (>50 bytes)
_MODULE_SIGNATURES: dict[str, list[str]] = {
    # ── Phase 1 : Fondations ───────────────────────────────────────────────
    "M0":  ["proto/event.proto", "server/oseye/core/schema.py", "agent/internal/platform/interface.go"],
    "M1":  ["agent/internal/chain/hasher.go", "agent/internal/signer/ed25519.go", "agent/internal/buffer/sqlite_buffer.go"],
    "M2":  ["agent/internal/platform/linux/driver.go", "agent/internal/platform/linux/ebpf/loader.go"],
    "M3":  ["agent/internal/transport/grpc_client.go"],
    "M4":  ["agent/cmd/oseye-agent/main.go"],
    "M5":  ["server/oseye/bus/memory.py", "server/oseye/bus/redis_streams.py"],
    "M6":  ["server/oseye/ingest/grpc_service.py", "server/oseye/ingest/validator.py"],
    "M7":  ["server/oseye/normalizer/engine.py"],
    "M8":  ["server/oseye/storage/backends/sqlite.py", "server/oseye/storage/repositories/event_repo.py"],
    "M9":  ["server/oseye/api/auth/jwt.py", "server/oseye/api/routers/events.py"],
    "M10": ["server/oseye/workers/storage_writer.py", "server/oseye/core/runner.py"],
    "M11": ["infra/docker/docker-compose.dev.yml", ".github/workflows/ci.yml"],
    # ── Phase 2 : Agent Go complet ────────────────────────────────────────
    "M12": ["agent/internal/platform/linux/fanotify/collector.go", "agent/internal/platform/linux/inotify/collector.go"],
    "M13": ["server/oseye/normalizer/adapters/linux/fanotify.py", "server/oseye/normalizer/adapters/linux/inotify.py"],
    "M14": ["agent/internal/mapper/mapper.go"],
    "M15": ["agent/internal/buffer/sqlite_buffer.go", "agent/internal/transport/grpc_client.go"],
    "M16": ["agent/internal/watchdog/watchdog.go"],
    "M17": ["agent/internal/policy/client.go", "agent/internal/commands/client.go"],
    "M18": ["server/oseye/normalizer/adapters/linux/auditd.py", "server/oseye/normalizer/adapters/linux/ebpf.py"],
    "M19": ["agent/internal/platform/linux/auditd/collector.go"],
    "M20": ["agent/internal/platform/linux/ebpf/collector.go"],
    # ── Phase 3 : Server — analyse et détection ──────────────────────────
    "M22": ["server/oseye/rule_engine/engine.py", "server/oseye/rule_engine/evaluator.py"],
    "M23": ["server/oseye/workers/rule_worker.py"],
    "M24": ["server/oseye/api/routers/rules.py", "server/oseye/api/routers/alerts.py"],
    # ── Phase 4 : ML, TI, corrélation ────────────────────────────────────
    "M25": ["server/oseye/ml_engine/engine.py", "server/oseye/ml_engine/classifier.py"],
    "M26": ["server/oseye/threat_intel/client.py", "server/oseye/threat_intel/cache.py"],
    "M27": ["server/oseye/correlation/engine.py"],
    # ── Phase 5 : Decision Engine ─────────────────────────────────────────
    "M28": ["server/oseye/decision/engine.py", "server/oseye/decision/journal.py", "server/oseye/decision/human_queue.py"],
    "M28b": ["server/oseye/api/routers/decisions.py"],
    # ── Phase 6 : Forensics ───────────────────────────────────────────────
    "M29": ["server/oseye/forensic/case_manager.py", "server/oseye/forensic/timeline.py", "server/oseye/forensic/snapshot.py"],
    "M29b": ["server/oseye/api/routers/cases.py"],
    # ── Phase 7 : Workers complets ────────────────────────────────────────
    "M30": ["server/oseye/workers/correlation_worker.py", "server/oseye/workers/decision_worker.py", "server/oseye/workers/ml_worker.py"],
    # ── Phase 8 : Policy Engine + Plugin SDK ──────────────────────────────
    "M31": ["server/oseye/policy/engine.py", "server/oseye/plugin/manager.py", "server/oseye/plugin/verifier.py", "server/oseye/plugin/sandbox.py"],
    # ── Phase 9 : UI React/TypeScript ─────────────────────────────────────
    "M32": ["ui/src/App.tsx", "ui/src/stores/authStore.ts", "ui/src/api/client.ts"],
    "M32b": ["ui/src/pages/Dashboard.tsx", "ui/src/pages/Alerts.tsx", "ui/src/pages/Events.tsx"],
    "M32c": ["ui/src/pages/Decisions.tsx", "ui/src/pages/Cases.tsx", "ui/src/pages/CaseDetail.tsx"],
    "M32d": ["ui/src/pages/Rules.tsx", "ui/src/pages/Incidents.tsx", "ui/src/pages/NetworkGraph.tsx"],
}


def detect_modules() -> dict[str, str]:
    """Return {module_id: 'implemented'|'partial'|'absent'} for all known modules."""
    status: dict[str, str] = {}
    for mod, files in _MODULE_SIGNATURES.items():
        existing = sum(
            1 for f in files
            if (ROOT / f).exists() and (ROOT / f).stat().st_size > 50
        )
        if existing == 0:
            status[mod] = "absent"
        elif existing < len(files):
            status[mod] = "partial"
        else:
            status[mod] = "implemented"
    return status
