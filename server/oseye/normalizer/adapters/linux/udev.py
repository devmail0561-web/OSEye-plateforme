"""Udev adapter — converts a raw udev JSON payload to a UniversalEvent."""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent


class UdevAdapter:
    """Convertit un payload JSON udev → UniversalEvent."""

    def normalize(self, raw_bytes: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        """Parse *raw_bytes* and return a normalised :class:`UniversalEvent`.

        * ``category`` = ``"device"``
        * ``type``     = ``payload["action"]`` (``add`` | ``remove``)
        * ``resource`` = ``devpath``
        """
        data: dict[str, Any] = json.loads(raw_bytes)

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="device",
            type=str(data.get("action", "")),
            severity="info",
            collector="udev",
            os="linux",
            resource=str(data.get("devpath", "")),
        )
