"""Fanotify adapter — converts a raw fanotify JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent


class FanotifyAdapter:
    """Convertit un payload JSON fanotify → UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse *raw_json* and return a normalised :class:`UniversalEvent`.

        * ``category`` = ``"file"``
        * ``type``     = ``payload["event_type"]`` (open/access/modify/close_write)
        * ``severity`` = ``"medium"`` for modify/close_write, else ``"info"``
        """
        data: dict[str, Any] = json.loads(raw_json)
        event_type = str(data.get("event_type", ""))

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="file",
            type=event_type,
            severity="medium" if event_type in ("modify", "close_write") else "info",
            collector="fanotify",
            os="linux",
            pid=int(data.get("pid", -1)),
            resource=str(data.get("path", "")),
        )
