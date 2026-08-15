"""Es adapter — Apple EndpointSecurity events → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts


class EsAdapter:
    """Convertit un payload JSON EndpointSecurity → UniversalEvent (audit).

    In production this receives events from the ES framework (process exec,
    file access, network). In CGO_ENABLED=0 builds the collector only emits
    a one-shot status event (available=false).
    """

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        event_type = str(data.get("event_type", "es_event"))
        severity = "info"

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="audit",
            type=event_type,
            severity=severity,
            collector="es",
            os="darwin",
            resource=str(data.get("message", ""))[:256],
        )
