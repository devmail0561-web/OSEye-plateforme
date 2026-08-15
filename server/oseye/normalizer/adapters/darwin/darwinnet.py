"""Darwinnet adapter — macOS netstat connections → UniversalEvent."""

from __future__ import annotations

import json
import uuid
from typing import Any

from oseye.core.schema import UniversalEvent
from oseye.normalizer.adapters.linux._utils import agent_ts, safe_int


class DarwinnetAdapter:
    """Convertit un payload JSON darwinnet → UniversalEvent (network)."""

    def normalize(self, raw_json: bytes, hostname: str, agent_id: str) -> UniversalEvent:
        data: dict[str, Any] = json.loads(raw_json)
        local_addr = str(data.get("local_addr", ""))
        remote_addr = str(data.get("remote_addr", ""))
        local_port = safe_int(data.get("local_port"))
        remote_port = safe_int(data.get("remote_port"))
        state = str(data.get("state", ""))
        proto = str(data.get("proto", "tcp"))

        is_external = remote_addr and not remote_addr.startswith(
            ("127.", "0.0.0.0", "::", "10.", "192.168.", "172.", "*")
        )
        severity = "low" if is_external else "info"

        return UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=agent_ts(data),
            hostname=hostname,
            agent_id=uuid.UUID(agent_id),
            category="network",
            type=state.lower() or "connection",
            severity=severity,
            collector="darwinnet",
            os="darwin",
            src_ip=local_addr,
            src_port=local_port,
            dst_ip=remote_addr,
            dst_port=remote_port,
            protocol=proto,
            resource=f"{local_addr}:{local_port} → {remote_addr}:{remote_port}",
        )
