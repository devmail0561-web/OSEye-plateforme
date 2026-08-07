"""Shared helpers for Linux normalizer adapters."""

from __future__ import annotations

import time
from typing import Any


def safe_int(value: Any, default: int = 0) -> int:
    """Safely coerce *value* to int.

    Handles:
    - None / JSON null → *default*  (C2/F13 fix: avoids TypeError on int(None))
    - empty string ""  → *default*  (F14 fix: avoids ValueError on int(""))
    - numeric string   → parsed int
    - float            → truncated int
    - int              → unchanged
    """
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return default
        try:
            return int(stripped)
        except ValueError:
            return default
    return default


def agent_ts(data: dict[str, Any]) -> int:
    """Return the agent-side timestamp from *data*, falling back to server time.

    H10/F01 fix: prefer the ``timestamp_ns`` field emitted by the Go collector
    so forensic timelines are accurate. Falls back to ``time.time_ns()`` only
    when the field is absent or non-numeric.
    """
    raw = data.get("timestamp_ns")
    if raw is not None:
        ts = safe_int(raw, default=-1)
        if ts > 0:
            return ts
    return time.time_ns()
