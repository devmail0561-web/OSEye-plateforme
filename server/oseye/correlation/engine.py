"""CorrelationEngine — M26.

Groups incoming alerts into Incidents using pluggable linker strategies.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from oseye.core.observability import get_logger
from oseye.core.schema import Incident, IncidentEvent

if TYPE_CHECKING:
    from oseye.core.schema import Alert
    from oseye.storage.repositories.incidents import SQLIncidentRepository

_log = get_logger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class CorrelationEngine:
    """Entry-point for the M26 Correlation Engine.

    Receives alerts, runs registered linkers, and persists Incidents via
    SQLIncidentRepository.

    Parameters
    ----------
    linkers:        List of linker instances (e.g. SameHostLinker).
    incident_repo:  SQLIncidentRepository for persistence.
    min_severity:   Minimum alert severity to process (default "medium").
    """

    def __init__(
        self,
        linkers: list[Any],
        incident_repo: SQLIncidentRepository,
        min_severity: str = "medium",
    ) -> None:
        self._linkers = linkers
        self._repo = incident_repo
        self._min_severity = min_severity

    async def process_alert(self, alert: Alert) -> Incident | None:
        """Correlate *alert* into an existing or new Incident.

        Returns the Incident (created or updated), or None if the alert is
        below *min_severity*.
        """
        if _SEVERITY_ORDER.get(alert.severity, -1) < _SEVERITY_ORDER[self._min_severity]:
            return None

        event = IncidentEvent(
            alert_id=alert.alert_id,
            timestamp=alert.created_at,
            severity=alert.severity,
            title=alert.title,
            hostname=alert.hostname,
            mitre_techniques=list(alert.mitre_techniques or []),
        )

        # Try each linker — use the first match
        for linker in self._linkers:
            existing: Incident | None = await linker.match(alert, self._repo)
            if existing is not None:
                await self._repo.add_alert(existing.incident_id, event)

                existing.severity = linker.max_severity(existing.severity, alert.severity)
                existing.updated_at = datetime.now(UTC)
                existing.alert_count += 1

                for technique in (alert.mitre_techniques or []):
                    if technique not in existing.mitre_tactics:
                        existing.mitre_tactics.append(technique)

                await self._repo.update(existing)

                _log.info(
                    "correlation_alert_linked",
                    alert_id=str(alert.alert_id),
                    incident_id=str(existing.incident_id),
                    linker=linker.name,
                )
                return existing

        # No linker matched — create a new incident
        incident = Incident(
            hostname=alert.hostname,
            severity=alert.severity,
            alert_ids=[alert.alert_id],
            alert_count=1,
            mitre_tactics=list(alert.mitre_techniques or []),
            timeframe_seconds=self._linkers[0]._timeframe if self._linkers else 300,
        )
        incident.timeline = [event]

        await self._repo.create(incident)

        _log.info(
            "correlation_incident_created",
            alert_id=str(alert.alert_id),
            incident_id=str(incident.incident_id),
            hostname=alert.hostname,
            severity=alert.severity,
        )
        return incident
