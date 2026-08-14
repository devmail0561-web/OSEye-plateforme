"""PidLineageLinker — correlates alerts that share the same process on a host.

Two alerts belong to the same attack chain when they originate from the same
process (entity_id == "hostname:pid") on the same host within a time window.
This catches multi-stage exploits where a single process opens a socket, reads
a credential file, and exfiltrates data — each generating a separate alert.

Score formula:
    0.0  — different host or outside timeframe
    0.6  — same host + same entity_id (same process)
    0.7  — same host + pid match (alert.pid == existing alert's pid in incident)
    +0.3 — MITRE technique overlap bonus (max total 1.0)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from oseye.core.schema import Alert, Incident

_BASE_ENTITY = 0.6
_BASE_PID = 0.7
_MITRE_BONUS_MAX = 0.3


class PidLineageLinker:
    """Links alerts from the same process (entity_id / pid) on the same host."""

    name = "pid_lineage"

    def __init__(self, timeframe_seconds: int = 300) -> None:
        self._timeframe = timeframe_seconds

    async def score(self, alert: "Alert", incident: "Incident") -> float:
        if alert.hostname != incident.hostname:
            return 0.0

        cutoff = datetime.now(UTC) - timedelta(seconds=self._timeframe)
        if incident.created_at < cutoff:
            return 0.0

        base = 0.0

        # Same entity_id → same process instance
        incident_entities = {e.title for e in incident.events} if incident.events else set()
        if alert.entity_id and any(alert.entity_id in e for e in incident_entities):
            base = _BASE_ENTITY
        elif alert.pid is not None:
            # Check if any alert in the incident has the same pid
            incident_pids = {
                int(e.title.split(":")[-1])
                for e in incident.events
                if ":" in e.title and e.title.split(":")[-1].isdigit()
            }
            if alert.pid in incident_pids:
                base = _BASE_PID

        if base == 0.0:
            return 0.0

        alert_techniques = set(alert.mitre_techniques or [])
        if alert_techniques:
            incident_tactics = set(incident.mitre_tactics)
            overlap = len(alert_techniques & incident_tactics) / len(alert_techniques)
            return min(1.0, base + _MITRE_BONUS_MAX * overlap)

        return base
