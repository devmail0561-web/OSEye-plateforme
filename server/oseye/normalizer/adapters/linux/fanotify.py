"""Fanotify adapter — converts a raw fanotify JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts, safe_int


class FanotifyAdapter:
    """Convertit un payload JSON fanotify -> UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse raw_json and return a normalised UniversalEvent.

        timestamp_ns uses the agent-side value when present (H10 fix).
        pid defaults to 0 for null/absent values (C2/F02 fix).
        """
        data: dict[str, Any] = json.loads(raw_json)
        event_type = str(data.get("event_type", ""))

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="file",
            type=event_type,
            severity="medium" if event_type in ("modify", "close_write") else "info",
            collector="fanotify",
            os="linux",
            pid=safe_int(data.get("pid")),
            resource=str(data.get("path", "")),
        )
