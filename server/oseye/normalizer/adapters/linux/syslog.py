"""Syslog adapter — converts a raw syslog JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts

_Severity = Literal["info", "low", "medium", "high", "critical"]


def _map_severity(s: str) -> _Severity:
    """Map a syslog severity name to a UniversalEvent severity."""
    if s in ("emerg", "emergency", "alert", "critical", "crit"):
        return "critical"
    if s in ("err", "error"):
        return "high"
    if s in ("warning", "warn"):
        return "medium"
    return "info"


class SyslogAdapter:
    """Convertit un payload JSON syslog -> UniversalEvent."""

    def normalize(self, raw_bytes: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse raw_bytes and return a normalised UniversalEvent.

        timestamp_ns uses the agent-side value when present (H10 fix).
        """
        data: dict[str, Any] = json.loads(raw_bytes)

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="log",
            type="syslog_entry",
            severity=_map_severity(str(data.get("severity", ""))),
            collector="syslog",
            os="linux",
            resource=str(data.get("program", "")),
        )
