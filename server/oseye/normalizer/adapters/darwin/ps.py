"""Ps adapter — macOS process snapshot → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts, safe_int
from oseye.normalizer.secret_masker import mask


class PsAdapter:
    """Convertit un payload JSON ps → UniversalEvent (process/snapshot)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        name = str(data.get("name", ""))
        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="process",
            type="snapshot",
            severity="info",
            collector="ps",
            os="darwin",
            pid=safe_int(data.get("pid")),
            ppid=safe_int(data.get("ppid")),
            uid=safe_int(data.get("uid")),
            process_name=mask(name),
        )
