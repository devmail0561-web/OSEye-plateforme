"""Registry adapter — Windows Registry changes → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts


class RegistryAdapter:
    """Convertit un payload JSON registry → UniversalEvent (audit)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        hive = str(data.get("hive", ""))
        key_path = str(data.get("key_path", ""))
        event_type = str(data.get("event_type", "key_changed"))

        # Persistence-related keys are higher severity
        persistence_keys = {"Run", "RunOnce", "Winlogon", "Services"}
        severity = "high" if any(k in key_path for k in persistence_keys) else "medium"

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="audit",
            type=event_type,
            severity=severity,
            collector="registry",
            os="windows",
            resource=f"{hive}\\{key_path}",
        )
