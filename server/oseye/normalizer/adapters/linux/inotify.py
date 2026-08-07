"""Inotify adapter — converts a raw inotify JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent


class InotifyAdapter:
    """Convertit un payload JSON inotify → UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse *raw_json* and return a normalised :class:`UniversalEvent`.

        * ``category`` = ``"file"``
        * ``type``     = ``payload["event_type"]``
        * ``resource`` = ``full_path`` or ``base_path``
        * ``severity`` = ``"medium"`` for create/delete/moved_* events, else ``"info"``
        """
        data: dict[str, Any] = json.loads(raw_json)
        event_type = str(data.get("event_type", ""))
        resource = str(data.get("full_path", "") or data.get("base_path", ""))

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="file",
            type=event_type,
            severity="medium" if event_type in ("create", "delete", "moved_from", "moved_to") else "info",  # noqa: E501
            collector="inotify",
            os="linux",
            resource=resource,
        )
