"""SameHostLinker — correlates alerts on the same host within a time window.

score() returns a float in [0, 1]:
  - 0.0  : does not match (different host, or outside timeframe, or low severity)
  - 0.5  : same host, within timeframe
  - 0.5–1.0 : same host + MITRE technique overlap (max 1.0 when all techniques match)

The score-based interface replaces the old binary match() so the CorrelationEngine
can compare multiple open incidents and pick the best one rather than the first.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oseye.core.schema import Alert, Incident

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_BASE_SCORE = 0.5
_MITRE_BONUS_MAX = 0.5  # extra score when all alert techniques are already in incident


class SameHostLinker:
    """Links alerts that share the same hostname within a configurable timeframe.

    Score formula:
        score = 0.5 (base if host+timeframe match)
              + 0.5 × (mitre_overlap / alert_techniques_count)

    Parameters
    ----------
    timeframe_seconds:
        Maximum age (in seconds) of an open incident to be eligible for linking.
    """

    name = "same_host_timeframe"

    def __init__(self, timeframe_seconds: int = 300) -> None:
        self._timeframe = timeframe_seconds

    async def score(
        self,
        alert: Alert,
        incident: Incident,
    ) -> float:
        """Return a match score in [0, 1].  0.0 means no match."""
        if _SEVERITY_ORDER.get(alert.severity, -1) < _SEVERITY_ORDER["medium"]:
            return 0.0

        if alert.hostname != incident.hostname:
            return 0.0

        cutoff = datetime.now(UTC) - timedelta(seconds=self._timeframe)
        if incident.created_at < cutoff:
            return 0.0

        # Base: host + timeframe matched
        base = _BASE_SCORE

        # MITRE bonus: fraction of alert's techniques already in the incident
        alert_techniques = set(alert.mitre_techniques or [])
        if alert_techniques:
            incident_tactics = set(incident.mitre_tactics)
            overlap = len(alert_techniques & incident_tactics) / len(alert_techniques)
            return base + _MITRE_BONUS_MAX * overlap

        return base

    # Kept for tests that call match() directly (backward compat shim)
    async def match(
        self,
        alert: Alert,
        incident_repo: object,
    ) -> object:
        """Backward-compat shim — returns first open incident for this host."""
        from oseye.storage.repositories.incidents import SQLIncidentRepository
        repo: SQLIncidentRepository = incident_repo  # type: ignore[assignment]
        since = datetime.now(UTC) - timedelta(seconds=self._timeframe)
        if _SEVERITY_ORDER.get(alert.severity, -1) < _SEVERITY_ORDER["medium"]:
            return None
        return await repo.find_open_for_host(alert.hostname, since)

    def max_severity(self, current: str, new: str) -> str:
        """Return whichever of current / new has the higher severity."""
        return current if _SEVERITY_ORDER[current] >= _SEVERITY_ORDER[new] else new
