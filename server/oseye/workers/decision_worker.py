"""Decision worker — consumes analysis:correlated, produces decisions.

Subscribes to ``analysis:correlated`` (published by CorrelationWorker).
For each incident message, loads the Incident + trigger Alert, calls
DecisionEngine.decide(), persists the Decision, then dispatches via
ActionExecutor.

Message format consumed (analysis:correlated)::

    {
        "incident_id": "<uuid>",
        "trigger_alert_id": "<uuid>"   // optional
    }

Messages published (via ActionExecutor):
    decisions:completed  — for ALERT / INVESTIGATE / ISOLATE / COLLECT_MORE / NOTIFY
    decisions:pending    — for REQUEST_HUMAN / ESCALATE
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING
from uuid import UUID

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.decision.action_executor import ActionExecutor
    from oseye.decision.engine import DecisionEngine
    from oseye.storage.repositories.alerts import SQLAlertRepository
    from oseye.storage.repositories.decisions import SQLDecisionRepository
    from oseye.storage.repositories.events import SQLEventRepository
    from oseye.storage.repositories.incidents import SQLIncidentRepository

_log = get_logger(__name__)

CONSUME_TOPIC = "analysis:correlated"


class DecisionWorker:
    """Drives the full Decision Engine pipeline for each correlated incident.

    Parameters
    ----------
    bus:             EventBus instance.
    engine:          DecisionEngine with journal + scorer + ML engine.
    decision_repo:   Persistence for Decision objects.
    incident_repo:   Load Incidents by ID.
    alert_repo:      Load trigger Alert by ID.
    event_repo:      Load trigger UniversalEvent for ML scoring (optional).
    action_executor: Dispatches side-effects after persisting.
    stop_event:      Optional asyncio.Event — worker exits when set.
    """

    def __init__(
        self,
        bus: EventBus,
        engine: DecisionEngine,
        decision_repo: SQLDecisionRepository,
        incident_repo: SQLIncidentRepository,
        alert_repo: SQLAlertRepository,
        action_executor: ActionExecutor,
        event_repo: SQLEventRepository | None = None,
        stop_event: asyncio.Event | None = None,
        ws_decision_manager: object | None = None,
    ) -> None:
        self._bus = bus
        self._engine = engine
        self._decision_repo = decision_repo
        self._incident_repo = incident_repo
        self._alert_repo = alert_repo
        self._event_repo = event_repo
        self._action_executor = action_executor
        self._stop_event = stop_event or asyncio.Event()
        self._ws_decision_manager = ws_decision_manager
        self._total_processed = 0
        self._total_decisions = 0

    async def run(self) -> None:
        """Main loop — runs until stop_event is set or task is cancelled."""
        _log.info("decision_worker_started", topic=CONSUME_TOPIC)

        try:
            async for message in await self._bus.subscribe(CONSUME_TOPIC):
                try:
                    payload = json.loads(message)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("decision_worker_parse_error", error=str(exc))
                    continue

                await self._process(payload)

                if self._stop_event.is_set():
                    break
        finally:
            _log.info(
                "decision_worker_stopped",
                processed=self._total_processed,
                decisions=self._total_decisions,
            )

    async def _process(self, payload: dict[str, object]) -> None:
        incident_id_str = str(payload.get("incident_id", ""))
        if not incident_id_str:
            _log.warning("decision_worker_missing_incident_id", payload=payload)
            return

        try:
            incident_id = UUID(incident_id_str)
        except ValueError:
            _log.warning("decision_worker_invalid_incident_id", incident_id=incident_id_str)
            return

        try:
            incident = await self._incident_repo.get(incident_id)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "decision_worker_incident_load_error",
                incident_id=incident_id_str,
                error=str(exc),
            )
            return

        if incident is None:
            _log.warning("decision_worker_incident_not_found", incident_id=incident_id_str)
            return

        # Optionally load the trigger alert.
        # F-06: payload.get() may return None (JSON null) — str(None) = "None"
        # which is non-empty and would cause UUID("None") to raise ValueError.
        # Guard explicitly against None and empty string.
        alert = None
        raw_alert_id = payload.get("trigger_alert_id")
        trigger_alert_id_str = str(raw_alert_id) if raw_alert_id is not None else ""
        if trigger_alert_id_str:
            try:
                alert = await self._alert_repo.get(UUID(trigger_alert_id_str))
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "decision_worker_alert_load_error",
                    alert_id=trigger_alert_id_str,
                    error=str(exc),
                )

        # Load the trigger event for ML scoring when possible.
        trigger_event = None
        if self._event_repo is not None and alert is not None:
            try:
                trigger_event = await self._event_repo.get(alert.trigger_event_id)
            except Exception as exc:  # noqa: BLE001
                _log.debug(
                    "decision_worker_event_load_error",
                    alert_id=trigger_alert_id_str,
                    error=str(exc),
                )

        self._total_processed += 1

        try:
            decision = await self._engine.decide(incident, alert=alert, trigger_event=trigger_event)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "decision_worker_engine_error",
                incident_id=incident_id_str,
                error=str(exc),
            )
            return

        try:
            await self._decision_repo.create(decision)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "decision_worker_persist_error",
                decision_id=str(decision.decision_id),
                error=str(exc),
            )
            # F-01: roll back journal so it stays consistent with the DB.
            await self._engine.rollback_journal(decision.prev_journal_hash)
            return

        self._total_decisions += 1

        # Broadcast to WebSocket clients
        if self._ws_decision_manager is not None:
            try:
                import json as _json
                await self._ws_decision_manager.broadcast(
                    _json.dumps({
                        "decision_id": str(decision.decision_id),
                        "decision_type": decision.decision_type,
                        "risk_score": getattr(decision, "risk_score", None),
                        "hostname": getattr(decision, "hostname", None),
                        "created_at": decision.created_at.isoformat(),
                    }).encode()
                )
            except Exception as exc:  # noqa: BLE001
                _log.debug("decision_worker_ws_broadcast_error", error=str(exc))

        try:
            await self._action_executor.execute(decision)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "decision_worker_execute_error",
                decision_id=str(decision.decision_id),
                error=str(exc),
            )
