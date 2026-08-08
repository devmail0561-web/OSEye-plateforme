"""SameHostLinker — correlates alerts on the same host within a time window."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oseye.core.schema import Alert, Incident
    from oseye.storage.repositories.incidents import SQLIncidentRepository

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class SameHostLinker:
    """Links alerts that share the same hostname within a configurable timeframe."""

    name = "same_host_timeframe"

    def __init__(self, timeframe_seconds: int = 300) -> None:
        self._timeframe = timeframe_seconds

    async def match(
        self,
        alert: Alert,
        incident_repo: SQLIncidentRepository,
    ) -> Incident | None:
        """Return the most recent open incident for this host, or None."""
        if _SEVERITY_ORDER.get(alert.severity, -1) < _SEVERITY_ORDER["medium"]:
            return None
        since = datetime.now(UTC) - timedelta(seconds=self._timeframe)
        return await incident_repo.find_open_for_host(alert.hostname, since)

    def max_severity(self, current: str, new: str) -> str:
        """Return whichever of current / new has the higher severity."""
        return current if _SEVERITY_ORDER[current] >= _SEVERITY_ORDER[new] else new
