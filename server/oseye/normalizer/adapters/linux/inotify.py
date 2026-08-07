"""Inotify adapter — converts a raw inotify JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts

_WARN_TYPES = frozenset({"create", "delete", "moved_from", "moved_to"})


class InotifyAdapter:
    """Convertit un payload JSON inotify -> UniversalEvent."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse raw_json and return a normalised UniversalEvent.

        resource uses full_path then base_path; None values produce "" not "None" (F08 fix).
        timestamp_ns uses the agent-side value when present (H10 fix).
        """
        data: dict[str, Any] = json.loads(raw_json)
        event_type = str(data.get("event_type", ""))
        # F08 fix: use `or ""` so JSON null fields produce "" not "None".
        resource = str(data.get("full_path") or data.get("base_path") or "")

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="file",
            type=event_type,
            severity="medium" if event_type in _WARN_TYPES else "info",
            collector="inotify",
            os="linux",
            resource=resource,
        )
