"""Toolhelp32 adapter — Windows process snapshot → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts, safe_int


class Toolhelp32Adapter:
    """Convertit un payload JSON toolhelp32 → UniversalEvent (process/snapshot)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="process",
            type="snapshot",
            severity="info",
            collector="toolhelp32",
            os="windows",
            pid=safe_int(data.get("pid")),
            ppid=safe_int(data.get("ppid")),
            process_name=str(data.get("name", "")),
        )
