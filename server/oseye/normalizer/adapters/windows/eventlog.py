"""Eventlog adapter — Windows Event Log → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts

_SEVERITY_MAP = {
    "error":          "high",
    "warning":        "medium",
    "information":    "info",
    "audit_success":  "info",
    "audit_failure":  "high",
}


class EventlogAdapter:
    """Convertit un payload JSON eventlog → UniversalEvent (log)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        event_type = str(data.get("event_type", "information"))
        severity = _SEVERITY_MAP.get(event_type, "info")

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="log",
            type=event_type,
            severity=severity,
            collector="eventlog",
            os="windows",
            resource=str(data.get("source", "")),
        )
