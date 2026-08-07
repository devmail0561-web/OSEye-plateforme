"""Journald adapter — converts a raw journald JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts, safe_int

_Severity = Literal["info", "low", "medium", "high", "critical"]


def _map_priority(p: str) -> _Severity:
    """Map a journald priority number or name to a UniversalEvent severity."""
    if p in ("0", "1", "2"):
        return "critical"
    if p == "3":
        return "high"
    if p == "4":
        return "medium"
    return "info"


class JournaldAdapter:
    """Convertit un payload JSON journald -> UniversalEvent."""

    def normalize(self, raw_bytes: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse raw_bytes and return a normalised UniversalEvent.

        pid uses safe_int to handle None and empty-string _PID values (C2/F14 fix).
        timestamp_ns uses the agent-side value when present (H10 fix).
        """
        data: dict[str, Any] = json.loads(raw_bytes)

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="log",
            type="journal_entry",
            severity=_map_priority(str(data.get("priority", ""))),
            collector="journald",
            os="linux",
            resource=str(data.get("unit", "")),
            process_name=str(data.get("comm", "") or data.get("identifier", "")),
            pid=safe_int(data.get("pid")),
        )
