"""ETW adapter — Windows Event Tracing → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts, safe_int

_SEVERITY_MAP = {
    "process_create":       "info",
    "process_exit":         "info",
    "logon_success":        "info",
    "logon_failure":        "medium",
    "logon_explicit_cred":  "high",
    "permissions_changed":  "medium",
    "service_installed":    "high",
    "file_access":          "low",
    "event":                "info",
}

_CATEGORY_MAP = {
    "process_create":       "process",
    "process_exit":         "process",
    "logon_success":        "user",
    "logon_failure":        "user",
    "logon_explicit_cred":  "user",
    "permissions_changed":  "audit",
    "service_installed":    "audit",
    "file_access":          "file",
}


class EtwAdapter:
    """Convertit un payload JSON ETW → UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        event_type = str(data.get("event_type") or data.get("EventType") or "event")
        # Default category is "audit" (not "process") for unknown event types —
        # unknown events are more likely to be administrative/status than process.
        category = _CATEGORY_MAP.get(event_type, "audit")
        severity = _SEVERITY_MAP.get(event_type, "info")

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category=category,
            type=event_type,
            severity=severity,
            collector="etw",
            os="windows",
            pid=safe_int(data.get("pid") or data.get("PID")),
            process_name=str(data.get("provider") or data.get("Provider") or ""),
            resource=str(data.get("message") or data.get("Message") or "")[:512],
        )
