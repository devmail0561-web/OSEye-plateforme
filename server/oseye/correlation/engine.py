"""CorrelationEngine — M26.

Groups incoming alerts into Incidents using pluggable linker strategies.

Corrections vs initial version
--------------------------------

1. Linkers multiples avec score — pas de "premier gagnant"
   L'ancienne logique prenait le premier linker qui matchait. Si deux linkers
   matchent le même incident mais avec des critères différents (host + MITRE),
   le second était ignoré. Désormais chaque linker retourne un score [0,1] ;
   on choisit le linker avec le score le plus élevé, et en cas d'égalité on
   préfère le plus spécifique (dernier dans la liste).

2. Incidents multiples par host
   find_open_for_host ne retournait qu'un seul incident. Si deux attaques
   distinctes touchent le même host simultanément, tout était fusionné.
   On passe maintenant par find_open_incidents_for_host (plusieurs résultats)
   et on sélectionne l'incident dont les tactics MITRE se recoupent le mieux
   avec l'alerte entrante. Nouvelle méthode ajoutée dans le repo.

3. Clôture automatique d'incident
   Un incident "open" sans nouvelle alerte depuis `auto_close_after_seconds`
   passe automatiquement au statut "resolved". close_stale_incidents() est
   conçu pour être appelé périodiquement par un worker de maintenance.

4. Défense contre les appels sans linker
   Si `linkers` est vide on ne peut pas accéder linkers[0]._timeframe et le
   crash était silencieux. On lève ValueError à l'init pour fail-fast.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from oseye.core.observability import get_logger
from oseye.core.schema import Incident, IncidentEvent

if TYPE_CHECKING:
    from oseye.core.schema import Alert
    from oseye.storage.repositories.incidents import SQLIncidentRepository

_log = get_logger(__name__)

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Default: close an incident that has received no new alert for 30 minutes
_DEFAULT_AUTO_CLOSE_SECONDS = 1800


class CorrelationEngine:
    """Entry-point for the M26 Correlation Engine.

    Parameters
    ----------
    linkers:
        List of linker instances. At least one required.
    incident_repo:
        SQLIncidentRepository for persistence.
    min_severity:
        Minimum alert severity to process (default "medium").
        W-09: setting this to "low" causes every alert to be correlated, which
        can be very slow on high-volume deployments. "medium" is the recommended
        default; override via configuration only if full coverage is required.
    auto_close_after_seconds:
        Incidents with no new alert for this duration are auto-closed.
        Set to 0 to disable auto-close.
    """

    def __init__(
        self,
        linkers: list[Any],
        incident_repo: SQLIncidentRepository,
        min_severity: str = "medium",
        auto_close_after_seconds: int = _DEFAULT_AUTO_CLOSE_SECONDS,
    ) -> None:
        if not linkers:
            raise ValueError("CorrelationEngine requires at least one linker")
        if min_severity not in _SEVERITY_ORDER:
            raise ValueError(
                f"Invalid min_severity: {min_severity!r}. Must be one of {list(_SEVERITY_ORDER)}"
            )
        self._linkers = linkers
        self._repo = incident_repo
        self._min_severity = min_severity
        self._auto_close_after = auto_close_after_seconds
        self._min_severity_ord: int = _SEVERITY_ORDER.get(min_severity, 0)
        self._max_timeframe: int = max(getattr(lnk, "_timeframe", 300) for lnk in linkers)

    async def get_incident(self, incident_id: UUID) -> Incident | None:
        """Return the Incident for *incident_id*, or None if not found."""
        return await self._repo.get(incident_id)

    async def process_alert(self, alert: Alert) -> Incident | None:
        """Correlate *alert* into an existing or new Incident.

        Returns the Incident (created or updated), or None if the alert is
        below *min_severity*.
        """
        if _SEVERITY_ORDER.get(alert.severity, -1) < self._min_severity_ord:
            return None

        event = IncidentEvent(
            alert_id=alert.alert_id,
            timestamp=alert.created_at,
            severity=alert.severity,
            title=alert.title,
            hostname=alert.hostname,
            mitre_techniques=list(alert.mitre_techniques or []),
        )

        # Correction 2: load all open incidents for this host, not just one
        # F-04: use the maximum timeframe across all linkers so incidents older
        # than linkers[0]._timeframe are not invisible when multiple linkers exist.
        since = datetime.now(UTC) - timedelta(seconds=self._max_timeframe)
        candidates = await self._repo.find_open_incidents_for_host(alert.hostname, since)
        if len(candidates) > 50:
            _log.warning(
                "correlation_candidates_capped",
                hostname=alert.hostname,
                total=len(candidates),
            )
            candidates = candidates[:50]

        # Correction 1: score every (linker, incident) pair, pick best match
        best_incident: Incident | None = None
        best_score: float = -1.0
        best_linker: Any = None

        for incident in candidates:
            for linker in self._linkers:
                score = await linker.score(alert, incident)
                if score > best_score:
                    best_score = score
                    best_incident = incident
                    best_linker = linker

        if best_incident is not None and best_score > 0.0:
            await self._repo.add_alert(best_incident.incident_id, event)
            best_incident.severity = best_linker.max_severity(
                best_incident.severity, alert.severity
            )
            best_incident.updated_at = datetime.now(UTC)
            best_incident.alert_count += 1
            if alert.alert_id not in best_incident.alert_ids:
                best_incident.alert_ids.append(alert.alert_id)
            for technique in (alert.mitre_techniques or []):
                if technique not in best_incident.mitre_tactics:
                    best_incident.mitre_tactics.append(technique)
            await self._repo.update(best_incident)
            _log.info(
                "correlation_alert_linked",
                alert_id=str(alert.alert_id),
                incident_id=str(best_incident.incident_id),
                linker=best_linker.name,
                score=round(best_score, 3),
            )
            return best_incident

        # No match — create a new incident
        incident = Incident(
            hostname=alert.hostname,
            severity=alert.severity,
            alert_ids=[alert.alert_id],
            alert_count=1,
            mitre_tactics=list(alert.mitre_techniques or []),
            # F-04: store the max timeframe so the incident window covers all linkers.
            timeframe_seconds=self._max_timeframe,
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

    async def close_stale_incidents(self) -> int:
        """Correction 3 — auto-close incidents with no recent activity.

        Returns the number of incidents closed.
        Should be called periodically (e.g. every 5 minutes) by a maintenance task.
        """
        if self._auto_close_after <= 0:
            return 0

        cutoff = datetime.now(UTC) - timedelta(seconds=self._auto_close_after)
        count = await self._repo.close_stale(cutoff)
        if count:
            _log.info("correlation_stale_incidents_closed", count=count)
        return count
