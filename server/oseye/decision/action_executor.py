"""Action Executor — triggers actions based on a completed Decision.

The 8 decision types and their effects:

    ALERT         — publish to decisions:completed (UI notification via WS)
    IGNORE        — no-op, log only
    ESCALATE      — publish to decisions:pending (requires further review)
    INVESTIGATE   — publish to decisions:completed + request forensic snapshot
    ISOLATE       — publish to decisions:completed + emit isolate command to agent
    REQUEST_HUMAN — publish to decisions:pending + enqueue in human approval queue
    COLLECT_MORE  — publish to decisions:completed + request additional collection
    NOTIFY        — publish to decisions:completed (external notification hook)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.core.schema import Decision

_log = get_logger(__name__)

TOPIC_COMPLETED = "decisions:completed"
TOPIC_PENDING = "decisions:pending"


class ActionExecutor:
    """Executes side-effects for a completed Decision.

    Parameters
    ----------
    bus:    EventBus — publishes to decisions:completed / decisions:pending.
    """

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus

    async def execute(self, decision: Decision) -> None:
        """Dispatch the decision to the appropriate topic(s)."""
        decision_type = decision.decision_type

        if decision_type == "IGNORE":
            _log.info(
                "action_ignore",
                decision_id=str(decision.decision_id),
                entity_id=decision.entity_id,
                final_score=decision.final_score,
            )
            return

        if decision_type in ("REQUEST_HUMAN", "ESCALATE"):
            await self._publish(TOPIC_PENDING, decision)
            _log.info(
                "action_pending",
                decision_type=decision_type,
                decision_id=str(decision.decision_id),
            )
        else:
            await self._publish(TOPIC_COMPLETED, decision)
            _log.info(
                "action_completed",
                decision_type=decision_type,
                decision_id=str(decision.decision_id),
                entity_id=decision.entity_id,
            )

        # Type-specific side effects
        if decision_type == "ISOLATE":
            await self._emit_isolate_command(decision)
        elif decision_type == "INVESTIGATE":
            await self._request_forensic_snapshot(decision)
        elif decision_type == "COLLECT_MORE":
            await self._request_additional_collection(decision)

    async def _publish(self, topic: str, decision: Decision) -> None:
        payload = json.dumps(
            {
                "decision_id": str(decision.decision_id),
                "decision_type": decision.decision_type,
                "entity_id": decision.entity_id,
                "final_score": decision.final_score,
                "requires_human": decision.requires_human,
                "trigger_alert_id": (
                    str(decision.trigger_alert_id) if decision.trigger_alert_id else None
                ),
                "incident_chain_id": (
                    str(decision.incident_chain_id) if decision.incident_chain_id else None
                ),
                "explanation": decision.explanation,
                "created_at": decision.created_at.isoformat(),
            }
        ).encode()
        try:
            await self._bus.publish(topic, payload)
        except Exception as exc:  # noqa: BLE001
            _log.error("action_publish_error", topic=topic, error=str(exc))

    async def _emit_isolate_command(self, decision: Decision) -> None:
        """Publish an isolate command to the policy:push topic for the entity."""
        topic = f"policy:push:{decision.entity_id}"
        payload = json.dumps(
            {
                "command": "isolate",
                "decision_id": str(decision.decision_id),
                "reason": decision.explanation,
            }
        ).encode()
        try:
            await self._bus.publish(topic, payload)
            _log.info("action_isolate_command_sent", entity_id=decision.entity_id)
        except Exception as exc:  # noqa: BLE001
            _log.error("action_isolate_command_error", entity_id=decision.entity_id, error=str(exc))

    async def _request_forensic_snapshot(self, decision: Decision) -> None:
        """Publish a forensic snapshot request."""
        topic = "forensics:snapshot:request"
        payload = json.dumps(
            {
                "decision_id": str(decision.decision_id),
                "entity_id": decision.entity_id,
                "incident_chain_id": (
                    str(decision.incident_chain_id) if decision.incident_chain_id else None
                ),
            }
        ).encode()
        try:
            await self._bus.publish(topic, payload)
            _log.info("action_forensic_snapshot_requested", entity_id=decision.entity_id)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "action_forensic_snapshot_error",
                entity_id=decision.entity_id,
                error=str(exc),
            )

    async def _request_additional_collection(self, decision: Decision) -> None:
        """Publish a request for additional telemetry collection."""
        topic = f"policy:push:{decision.entity_id}"
        payload = json.dumps(
            {
                "command": "collect_more",
                "decision_id": str(decision.decision_id),
                "reason": decision.explanation,
            }
        ).encode()
        try:
            await self._bus.publish(topic, payload)
            _log.info("action_collect_more_sent", entity_id=decision.entity_id)
        except Exception as exc:  # noqa: BLE001
            _log.error("action_collect_more_error", entity_id=decision.entity_id, error=str(exc))
