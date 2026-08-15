"""Kqueue adapter — macOS file system events → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts

_SEVERITY_MAP = {
    "write":   "low",
    "delete":  "medium",
    "rename":  "low",
    "attrib":  "low",
    "change":  "info",
}

_SENSITIVE_PATHS = (
    "/etc/", "/usr/bin/", "/usr/sbin/",
    "/Library/LaunchAgents", "/Library/LaunchDaemons",
    "/System/", "/private/etc/",
)


class KqueueAdapter:
    """Convertit un payload JSON kqueue → UniversalEvent (file)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        path = str(data.get("path", ""))
        event_type = str(data.get("event_type", "change"))

        severity = _SEVERITY_MAP.get(event_type, "info")
        if any(path.startswith(p) for p in _SENSITIVE_PATHS):
            severity = "high" if event_type == "delete" else "medium"

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="file",
            type=event_type,
            severity=severity,
            collector="kqueue",
            os="darwin",
            resource=path,
        )
