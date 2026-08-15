"""Fswatch adapter — Windows ReadDirectoryChangesW → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts

_SEVERITY_MAP = {
    "create": "low",
    "delete": "medium",
    "modify": "low",
    "rename": "low",
    "unknown": "info",
}


class FswatchAdapter:
    """Convertit un payload JSON fswatch → UniversalEvent (file)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        path = str(data.get("path", ""))
        name = str(data.get("name", ""))
        event_type = str(data.get("event_type", "unknown"))
        # rstrip path separator before joining to avoid double backslash
        # when the collector includes a trailing separator in "path".
        full_path = f"{path.rstrip(chr(92))}\\{name}" if name else path

        severity = _SEVERITY_MAP.get(event_type, "info")
        # Elevated severity for sensitive system paths
        sensitive = ("\\System32", "\\SysWOW64", "\\Startup", "\\Services")
        if any(s in full_path for s in sensitive):
            severity = "high" if event_type in ("create", "delete") else severity

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="file",
            type=event_type,
            severity=severity,
            collector="fswatch",
            os="windows",
            resource=full_path,
        )
