"""UserActivityLinker — correlates alerts from the same user on a host.

The entity_id on alerts is "hostname:pid". The uid is not stored directly on
Alert, but process-based entity_ids share the same process namespace per user.
This linker uses the alert's process_name as a proxy for user context: alerts
from well-known user-privilege escalation chains (sudo, su, pkexec) are linked
regardless of PID.

Practically: links alerts where the process_name appears in the incident's
existing alert titles, within a time window — useful for tracking a single
attacker session across multiple tools (e.g. ssh → sudo → find → curl).

Score formula:
    0.0  — different host or outside timeframe
    0.5  — same host + process_name match in incident
    0.8  — same host + process_name match + MITRE technique overlap
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oseye.core.schema import Alert, Incident

_PRIVESC_NAMES = frozenset({"sudo", "su", "pkexec", "doas", "newgrp", "runuser"})
_BASE_PROC = 0.5
_PRIVESC_BONUS = 0.15
_MITRE_BONUS_MAX = 0.35


class UserActivityLinker:
    """Links alerts that share a process_name on the same host within a window."""

    name = "user_activity"

    def __init__(self, timeframe_seconds: int = 600) -> None:
        self._timeframe = timeframe_seconds

    async def score(self, alert: "Alert", incident: "Incident") -> float:
        if alert.hostname != incident.hostname:
            return 0.0

        cutoff = datetime.now(UTC) - timedelta(seconds=self._timeframe)
        if incident.created_at < cutoff:
            return 0.0

        if not alert.process_name:
            return 0.0

        incident_procs = {e.title for e in incident.events} if incident.events else set()

        # Direct process_name overlap with any incident alert title
        matched = any(alert.process_name in t for t in incident_procs)
        if not matched:
            return 0.0

        base = _BASE_PROC
        if alert.process_name in _PRIVESC_NAMES:
            base += _PRIVESC_BONUS

        alert_techniques = set(alert.mitre_techniques or [])
        if alert_techniques:
            incident_tactics = set(incident.mitre_tactics)
            overlap = len(alert_techniques & incident_tactics) / len(alert_techniques)
            return min(1.0, base + _MITRE_BONUS_MAX * overlap)

        return base
