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
