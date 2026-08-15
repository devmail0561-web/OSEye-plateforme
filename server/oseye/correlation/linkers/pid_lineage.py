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
from typing import TYPE_CHECKING

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

    async def score(self, alert: Alert, incident: Incident) -> float:
        if alert.hostname != incident.hostname:
            return 0.0

        cutoff = datetime.now(UTC) - timedelta(seconds=self._timeframe)
        if incident.created_at < cutoff:
            return 0.0

        base = 0.0

        timeline = incident.timeline or []

        # Same entity_id prefix in incident timeline titles: entity_id is "hostname:pid",
        # so we check for exact token match (word-boundary) rather than substring to
        # avoid spurious matches against arbitrary title text.
        if alert.entity_id and any(
            f" {alert.entity_id} " in f" {e.title} " or e.title == alert.entity_id
            for e in timeline
        ):
            base = _BASE_ENTITY
        elif alert.pid is not None:
            # Parse pids from timeline entries whose title ends with ":PID" (entity_id format).
            incident_pids = {
                int(e.title.rsplit(":", 1)[-1])
                for e in timeline
                if ":" in e.title and e.title.rsplit(":", 1)[-1].isdigit()
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
