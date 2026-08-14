"""Action Executor — triggers actions based on a completed Decision.

The 8 decision types and their effects:

    ALERT         — publish to decisions:completed (UI notification via WS)
    IGNORE        — no-op, log only
    ESCALATE      — publish to decisions:pending (requires further review)
    INVESTIGATE   — publish to decisions:completed + request forensic snapshot
    ISOLATE       — publish to decisions:completed + emit BLOCK_IP command to agent
    REQUEST_HUMAN — publish to decisions:pending + enqueue in human approval queue
    COLLECT_MORE  — publish to decisions:completed + request additional collection
    NOTIFY        — publish to decisions:completed (external notification hook)

CIA principles:
    Confidentialité : commands transit via mTLS-protected gRPC StreamCommands channel.
    Intégrité       : each command carries a unique command_id (UUID) so the agent
                      can detect replays and the server can correlate ActionReports.
    Disponibilité   : commands are published to the bus; if the agent is offline the
                      message is dropped but recorded in response_actions as pending_report
                      so the operator can see it and retry.
"""

from __future__ import annotations

import ipaddress
import json
import uuid
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.core.schema import Alert, Decision

_log = get_logger(__name__)

TOPIC_COMPLETED = "decisions:completed"
TOPIC_PENDING   = "decisions:pending"


class ActionExecutor:
    """Executes side-effects for a completed Decision.

    Parameters
    ----------
    bus:    EventBus — publishes to decisions:completed / decisions:pending
                       and to commands:{cn} for response commands.
    """

    def __init__(self, bus: EventBus, response_actions_repo=None) -> None:
        self._bus = bus
        # Optional repository for persisting pending response actions.
        # When provided, every emitted command is recorded so offline agents
        # don't silently lose commands (D-01 fix).
        self._response_actions_repo = response_actions_repo

    async def execute(self, decision: Decision, alert: Alert | None = None) -> None:
        """Dispatch the decision to the appropriate topic(s)."""
        decision_type = decision.decision_type
        # decision_types is the full set (e.g. ["ALERT", "ISOLATE"]).
        # Populated by the engine; empty for decisions loaded from DB.
        decision_types = decision.decision_types

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

        # Multi-type side effects — each action can coexist with ALERT.
        # CIA — Intégrité : command_id ties each command to this decision.
        # decision_types is empty for decisions loaded from DB (only decision_type
        # is persisted); fall back to [decision_type] so side-effects still fire.
        effective_types: list[str] = decision_types if decision_types else [decision_type]
        if "ISOLATE" in effective_types:
            command_id = await self._emit_block_ip_command(decision, alert)
            if command_id and self._response_actions_repo is not None:
                import datetime

                from oseye.storage.models import ResponseAction
                action = ResponseAction(
                    command_id=command_id,
                    command_type="BLOCK_IP",
                    agent_cn=decision.entity_id,
                    status="pending",
                    created_at=datetime.datetime.now(datetime.UTC),
                )
                try:
                    await self._response_actions_repo.save(action)
                except Exception as exc:
                    import logging
                    logging.getLogger(__name__).warning(
                        "action_executor: failed to persist pending BLOCK_IP",
                        extra={"error": str(exc)},
                    )
        if "INVESTIGATE" in effective_types:
            await self._request_forensic_snapshot(decision)
        if "COLLECT_MORE" in effective_types:
            await self._request_additional_collection(decision)
        if "NOTIFY" in effective_types:
            await self._emit_notification(decision)

    async def execute_after_approval(
        self, decision: Decision, alert: Alert | None = None
    ) -> None:
        """Execute response commands that require human approval (score > 80).

        Called by HumanApprovalQueue after an operator approves the decision.
        KILL_PROCESS is only issued here — never autonomously.
        """
        if not decision.requires_human:
            return

        await self._emit_kill_process_command(decision, alert)

    async def emit_rollback(self, cn: str, command_id: str, command_type: str,
                            payload: dict) -> None:
        """Send a rollback command to the agent identified by *cn*.

        Called when an admin explicitly rolls back an executed action.
        Maps command_type → rollback_type:
            BLOCK_IP       → UNBLOCK_IP
            QUARANTINE_FILE → RESTORE_FILE
        """
        rollback_map = {
            "BLOCK_IP":        "UNBLOCK_IP",
            "QUARANTINE_FILE": "RESTORE_FILE",
        }
        rollback_type = rollback_map.get(command_type)
        if not rollback_type:
            _log.warning("emit_rollback: no rollback for type", command_type=command_type)
            return

        rollback_payload = dict(payload)
        # For RESTORE_FILE we need quarantine_path and original_path.
        # These were recorded in ResponseActionRow.payload at execution time.

        await self._send_command(cn, rollback_type, rollback_payload)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _publish(self, topic: str, decision: Decision) -> None:
        payload = json.dumps(
            {
                "decision_id":      str(decision.decision_id),
                "decision_type":    decision.decision_type,
                "entity_id":        decision.entity_id,
                "final_score":      decision.final_score,
                "requires_human":   decision.requires_human,
                "trigger_alert_id": (
                    str(decision.trigger_alert_id) if decision.trigger_alert_id else None
                ),
                "incident_chain_id": (
                    str(decision.incident_chain_id) if decision.incident_chain_id else None
                ),
                "explanation":      decision.explanation,
                "created_at":       decision.created_at.isoformat(),
            }
        ).encode()
        try:
            await self._bus.publish(topic, payload)
        except Exception as exc:  # noqa: BLE001
            _log.error("action_publish_error", topic=topic, error=str(exc))

    async def _send_command(
        self, cn: str, command_type: str, payload: dict
    ) -> str:
        """Publish an AgentCommand to commands:{cn} and return the command_id.

        CIA — Disponibilité : publishes to the bus; if the agent's StreamCommands
        stream is not open the message is dropped by the bus (no persistence in
        the bus layer). The caller must persist the command_id in response_actions
        before calling this method so the action is visible to the operator.
        """
        command_id = str(uuid.uuid4())
        message = json.dumps(
            {
                "command_id":   command_id,
                "command_type": command_type,
                "payload":      payload,
            }
        ).encode()
        topic = f"commands:{cn}"
        try:
            await self._bus.publish(topic, message)
            _log.info(
                "command_sent",
                command_type=command_type,
                command_id=command_id,
                cn=cn,
            )
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "command_send_error",
                command_type=command_type,
                cn=cn,
                error=str(exc),
            )
        return command_id

    async def _emit_block_ip_command(
        self, decision: Decision, alert: Alert | None
    ) -> str | None:
        """Emit BLOCK_IP targeting the alert's dst_ip (act-then-notify).

        Returns the command_id so the caller can persist it in response_actions.
        """
        dst_ip = _extract_dst_ip(alert)
        if not dst_ip:
            _log.info(
                "action_isolate_no_ip",
                decision_id=str(decision.decision_id),
                note="no dst_ip available — BLOCK_IP skipped",
            )
            return None

        try:
            ipaddress.ip_address(dst_ip)
        except ValueError:
            _log.warning(
                "action_isolate_invalid_ip",
                decision_id=str(decision.decision_id),
                dst_ip=dst_ip,
            )
            return None

        # entity_id is the CN of the agent (hostname)
        cn = decision.entity_id
        return await self._send_command(
            cn,
            "BLOCK_IP",
            {
                "ip":          dst_ip,
                "decision_id": str(decision.decision_id),
            },
        )

    async def _emit_kill_process_command(
        self, decision: Decision, alert: Alert | None
    ) -> str | None:
        """Emit KILL_PROCESS — only after explicit human approval.

        CIA — Intégrité : PID and process_name are sent together so the agent
        can verify the PID has not been recycled before killing.
        """
        pid, process_name = _extract_process(alert)
        if pid is None:
            _log.info(
                "action_kill_no_pid",
                decision_id=str(decision.decision_id),
                note="no pid available — KILL_PROCESS skipped",
            )
            return None

        cn = decision.entity_id
        return await self._send_command(
            cn,
            "KILL_PROCESS",
            {
                "pid":          pid,
                "process_name": process_name,
                "decision_id":  str(decision.decision_id),
            },
        )

    async def _request_forensic_snapshot(self, decision: Decision) -> None:
        topic = "forensics:snapshot:request"
        payload = json.dumps(
            {
                "decision_id":      str(decision.decision_id),
                "entity_id":        decision.entity_id,
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

    async def _emit_notification(self, decision: Decision) -> None:
        """Publish a NOTIFY event to notifications:pending.

        Consumed by ExporterPlugin instances (Slack, PagerDuty, email…)
        via the IPC socket. The core server has no direct notification dependency.
        """
        topic = "notifications:pending"
        payload = json.dumps(
            {
                "decision_id":   str(decision.decision_id),
                "entity_id":     decision.entity_id,
                "final_score":   decision.final_score,
                "explanation":   decision.explanation,
                "created_at":    decision.created_at.isoformat(),
            }
        ).encode()
        try:
            await self._bus.publish(topic, payload)
            _log.info("action_notify_published", entity_id=decision.entity_id)
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "action_notify_failed",
                entity_id=decision.entity_id,
                error=str(exc),
            )
            # Note: no retry — notifications are best-effort

    async def _request_additional_collection(self, decision: Decision) -> None:
        topic = f"policy:push:{decision.entity_id}"
        payload = json.dumps(
            {
                "command":     "collect_more",
                "decision_id": str(decision.decision_id),
                "reason":      decision.explanation,
            }
        ).encode()
        try:
            await self._bus.publish(topic, payload)
            _log.info("action_collect_more_sent", entity_id=decision.entity_id)
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "action_collect_more_error",
                entity_id=decision.entity_id,
                error=str(exc),
            )


# ------------------------------------------------------------------
# Helpers — extract indicators from alerts
# ------------------------------------------------------------------

def _extract_dst_ip(alert: Alert | None) -> str | None:
    if alert is None:
        return None
    # Trigger event metadata is not directly on Alert — check extra fields.
    # Alerts produced by the rule engine carry the dst_ip in their description
    # or can be looked up from the trigger event. Here we do a best-effort
    # extraction from any alert metadata field that holds an IP.
    return getattr(alert, "dst_ip", None)


def _extract_process(alert: Alert | None) -> tuple[int | None, str]:
    if alert is None:
        return None, ""
    pid = getattr(alert, "pid", None)
    process_name = getattr(alert, "process_name", "")
    return pid, process_name
