"""Unifiedlog adapter — Apple Unified Log → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts, safe_int

_SEVERITY_MAP = {
    "fault":    "critical",
    "error":    "high",
    "warning":  "medium",
    "info":     "info",
    "debug":    "info",
    "default":  "info",
}

_ELEVATED_PROCESSES = {"sudo", "sshd", "su", "login", "SecurityAgent"}


class UnifiedlogAdapter:
    """Convertit un payload JSON unifiedlog → UniversalEvent (log)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        process = str(data.get("process", ""))
        level = str(data.get("level", "info")).lower()
        message = str(data.get("message", ""))
        severity = _SEVERITY_MAP.get(level, "info")

        # Elevate severity for security-relevant processes
        if process in _ELEVATED_PROCESSES and severity == "info":
            severity = "medium"

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="log",
            type="log",
            severity=severity,
            collector="unifiedlog",
            os="darwin",
            pid=safe_int(data.get("pid")),
            process_name=process,
            resource=message[:512],
        )
