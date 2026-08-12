"""Correlation worker — consumes alerts:created and groups them into Incidents.

Subscribes to ``alerts:created`` (published by RuleWorker for every alert,
regardless of whether network indicators are present).  This ensures that
non-network alerts (filesystem, process, privilege escalation…) reach the
CorrelationWorker and subsequently the DecisionWorker.

For each message, loads the alert from alert_repo, calls engine.process_alert,
then stamps alert.incident_chain_id with the resulting incident's ID.
Publishes ``analysis:correlated`` for the DecisionWorker.

Message format consumed (alerts:created)::

    {
        "alert_id": "<uuid>"
    }

Message format published (analysis:correlated)::

    {
        "incident_id": "<uuid>",
        "trigger_alert_id": "<uuid>"
    }
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from uuid import UUID

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.correlation.engine import CorrelationEngine
    from oseye.storage.repositories.alerts import SQLAlertRepository

_log = get_logger(__name__)

CONSUME_TOPIC = "alerts:created"
PUBLISH_TOPIC = "analysis:correlated"

# F-03: severity order used to detect escalation after process_alert().
_SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class CorrelationWorker:
    """Consumes alerts:enriched, correlates alerts into Incidents.

    Parameters
    ----------
    bus:        EventBus instance.
    engine:     Configured CorrelationEngine.
    alert_repo: Used to load and update alerts.
    stop_event: Optional asyncio.Event — worker exits when set.
    """

    def __init__(
        self,
        bus: EventBus,
        engine: CorrelationEngine,
        alert_repo: SQLAlertRepository,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        self._bus = bus
        self._engine = engine
        self._alert_repo = alert_repo
        self._stop_event = stop_event or asyncio.Event()
        self._total_processed = 0
        self._total_correlated = 0

    async def run(self) -> None:
        """Main loop — runs until stop_event is set or task is cancelled."""
        _log.info("correlation_worker_started", topic=CONSUME_TOPIC)

        # Periodic task: auto-close stale incidents every 5 minutes.
        stale_task = asyncio.create_task(self._stale_incidents_loop())

        try:
            async for message in await self._bus.subscribe(CONSUME_TOPIC):
                try:
                    payload = json.loads(message)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("correlation_worker_parse_error", error=str(exc))
                    continue

                await self._process(payload)

                if self._stop_event.is_set():
                    break
        finally:
            stale_task.cancel()
            try:
                await stale_task
            except asyncio.CancelledError:
                pass
            _log.info(
                "correlation_worker_stopped",
                processed=self._total_processed,
                correlated=self._total_correlated,
            )

    async def _stale_incidents_loop(self) -> None:
        """Close incidents with no activity for auto_close_after_seconds every 5 min."""
        while True:
            await asyncio.sleep(300)
            try:
                closed = await self._engine.close_stale_incidents()
                if closed:
                    _log.info("stale_incidents_closed", count=closed)
            except Exception as exc:  # noqa: BLE001
                _log.warning("stale_incidents_close_error", error=str(exc))

    async def _process(self, payload: dict[str, object]) -> None:
        alert_id_str: str = str(payload.get("alert_id", ""))
        if not alert_id_str:
            _log.warning("correlation_worker_missing_alert_id", payload=payload)
            return

        try:
            alert_id = UUID(alert_id_str)
        except ValueError:
            _log.warning("correlation_worker_invalid_alert_id", alert_id=alert_id_str)
            return

        try:
            alert = await self._alert_repo.get(alert_id)
        except Exception as exc:  # noqa: BLE001
            _log.error("correlation_worker_alert_load_error", alert_id=alert_id_str, error=str(exc))
            return

        if alert is None:
            _log.warning("correlation_worker_alert_not_found", alert_id=alert_id_str)
            return

        self._total_processed += 1

        # F-03: snapshot the incident severity *before* process_alert() so we can
        # detect escalation after the call.
        incident_before_severity: str | None = None
        if alert.incident_chain_id is not None:
            # There may already be an incident for this alert; try to read it.
            try:
                existing = await self._engine.get_incident(alert.incident_chain_id)
                if existing is not None:
                    incident_before_severity = existing.severity
            except Exception as exc:  # noqa: BLE001
                _log.warning("correlation_worker_snapshot_error", error=str(exc))  # best-effort

        try:
            incident = await self._engine.process_alert(alert)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "correlation_worker_engine_error",
                alert_id=alert_id_str,
                error=str(exc),
            )
            return

        if incident is None:
            # Alert below min_severity — no correlation needed
            return

        self._total_correlated += 1

        # Stamp the alert with its incident chain ID if not already set
        if alert.incident_chain_id != incident.incident_id:
            alert.incident_chain_id = incident.incident_id
            try:
                await self._alert_repo.update(alert)
            except Exception as exc:  # noqa: BLE001
                _log.error(
                    "correlation_worker_alert_update_error",
                    alert_id=alert_id_str,
                    error=str(exc),
                )
                return

        _log.info(
            "correlation_worker_correlated",
            alert_id=alert_id_str,
            incident_id=str(incident.incident_id),
            hostname=incident.hostname,
            severity=incident.severity,
        )

        # F-03: notify DecisionWorker when:
        #   1. The incident is newly created (alert_count == 1), OR
        #   2. The incident's severity escalated (e.g. medium → critical).
        # This ensures the pipeline is re-triggered on severity escalation while
        # still preventing duplicate ISOLATE commands for non-escalating updates.
        is_new = incident.alert_count == 1
        severity_escalated = (
            incident_before_severity is not None
            and _SEVERITY_ORDER.get(incident.severity, -1)
            > _SEVERITY_ORDER.get(incident_before_severity, -1)
        )
        if not is_new and not severity_escalated:
            return

        correlated_payload = json.dumps(
            {
                "incident_id": str(incident.incident_id),
                "trigger_alert_id": alert_id_str,
            }
        ).encode()
        try:
            await self._bus.publish(PUBLISH_TOPIC, correlated_payload)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "correlation_worker_publish_error",
                incident_id=str(incident.incident_id),
                error=str(exc),
            )
