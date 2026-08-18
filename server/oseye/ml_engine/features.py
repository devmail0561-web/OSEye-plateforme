"""Feature extraction for ML models — UniversalEvent → fixed-length float vector.

Feature vector (10 dims):
  [0] category_ord   : file=0 process=1 network=2 user=3 device=4 log=5 audit=6
  [1] severity_ord   : info=0 low=1 medium=2 high=3 critical=4
  [2] uid_norm       : min(uid/65535, 1.0)
  [3] is_root        : 1.0 if uid==0
  [4] hour_norm      : timestamp_ns hour-of-day / 23
  [5] dst_port_norm  : min(dst_port/65535, 1.0) — 0 if absent
  [6] bytes_sent_log : log1p(bytes_sent) / 40 capped — 0 if absent
  [7] bytes_recv_log : log1p(bytes_recv) / 40 capped — 0 if absent
  [8] result_ok      : 1.0 if result=="success", else 0.0
  [9] proc_hash      : stable float fingerprint of process_name in [0,1]

All values are in [0, 1] so HST and LR converge without scaling.
"""

from __future__ import annotations

import math
from functools import lru_cache

from oseye.core.observability import get_logger
from oseye.core.schema import UniversalEvent

_log = get_logger(__name__)

_CATEGORY_ORD: dict[str, float] = {
    "file": 0.0, "process": 1.0, "network": 2.0,
    "user": 3.0, "device": 4.0, "log": 5.0, "audit": 6.0,
}
_CATEGORY_MAX = 6.0

_SEVERITY_ORD: dict[str, float] = {
    "info": 0.0, "low": 1.0, "medium": 2.0, "high": 3.0, "critical": 4.0,
}
_SEVERITY_MAX = 4.0

_LOG_CAP = 40.0  # log1p(2^40) ≈ 27.7 — sufficient for multi-GB transfers


def extract(event: UniversalEvent) -> dict[str, float]:
    """Return a feature dict compatible with River estimators."""
    hour = (event.timestamp_ns // 3_600_000_000_000) % 24

    proc_hash = _stable_hash_norm(event.process_name)

    if event.category not in _CATEGORY_ORD:
        _log.warning(
            "features_unknown_category",
            category=event.category,
            event_id=str(event.event_id),
        )

    # ML-05: use min/max double-clamp for all normalized fields so that
    # negative or out-of-range input values never escape [0, 1].
    return {
        "category_ord": min(max(_CATEGORY_ORD.get(event.category, 0.0) / _CATEGORY_MAX, 0.0), 1.0),
        "severity_ord": min(max(_SEVERITY_ORD.get(event.severity, 0.0) / _SEVERITY_MAX, 0.0), 1.0),
        "uid_norm": min(max(event.uid / 65535.0, 0.0), 1.0),
        "is_root": 1.0 if event.uid == 0 else 0.0,
        "hour_norm": min(max(hour / 23.0, 0.0), 1.0),
        "dst_port_norm": min(max((event.dst_port or 0) / 65535.0, 0.0), 1.0),
        "bytes_sent_log": min(max(math.log1p(event.bytes_sent or 0) / _LOG_CAP, 0.0), 1.0),
        "bytes_recv_log": min(max(math.log1p(event.bytes_recv or 0) / _LOG_CAP, 0.0), 1.0),
        "result_ok": 1.0 if event.result == "success" else 0.0,
        "proc_hash": proc_hash,
    }


@lru_cache(maxsize=512)
def _stable_hash_norm(s: str) -> float:
    """Deterministic [0,1] float from a string (FNV-1a 32-bit)."""
    h = 2166136261
    for ch in s.encode():
        h ^= ch
        h = (h * 16777619) & 0xFFFFFFFF
    return h / 0xFFFFFFFF
