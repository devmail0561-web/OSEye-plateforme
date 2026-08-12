"""Human approval queue — manages decisions awaiting operator review.

Decisions with ``requires_human=True`` land here with a timeout.
After *timeout_at*, they are auto-expired (human_decision set to "rejected").
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.core.schema import Decision
    from oseye.decision.action_executor import ActionExecutor
    from oseye.storage.repositories.alerts import SQLAlertRepository
    from oseye.storage.repositories.decisions import SQLDecisionRepository

_log = get_logger(__name__)


class HumanApprovalQueue:
    """Tracks pending human decisions and handles timeouts.

    Parameters
    ----------
    decision_repo:   Repository used to persist approval outcomes.
    poll_interval:   Seconds between timeout sweeps (default 30).
    """

    def __init__(
        self,
        decision_repo: SQLDecisionRepository,
        poll_interval: int = 30,
        action_executor: ActionExecutor | None = None,
        alert_repo: SQLAlertRepository | None = None,
    ) -> None:
        self._repo = decision_repo
        self._poll_interval = poll_interval
        self._stop = asyncio.Event()
        # CIA — Disponibilité : after human approval, push the response command
        # to the agent immediately via ActionExecutor.execute_after_approval().
        self._executor = action_executor
        self._alert_repo = alert_repo

    async def run(self) -> None:
        """Background loop — expires timed-out pending decisions."""
        _log.info("human_queue_started")
        try:
            while not self._stop.is_set():
                try:
                    await self._expire_timeout()
                except Exception as exc:  # noqa: BLE001
                    _log.error("human_queue_sweep_error", error=str(exc))
                try:
                    await asyncio.wait_for(
                        self._stop.wait(), timeout=self._poll_interval
                    )
                    return  # stop was signaled
                except (TimeoutError, asyncio.CancelledError):
                    if self._stop.is_set():
                        return
        finally:
            _log.info("human_queue_stopped")

    def stop(self) -> None:
        self._stop.set()

    async def approve(self, decision_id: UUID, operator: str, note: str = "") -> Decision | None:
        """Record an operator approval for *decision_id* and trigger response commands.

        After persisting the approval, calls ActionExecutor.execute_after_approval()
        to push KILL_PROCESS (or other post-approval commands) to the agent.
        Returns the updated Decision, or None if not found / already decided.
        """
        decision = await self._update_decision(decision_id, "approved", operator, note)
        if decision is not None and self._executor is not None:
            try:
                alert = None
                if self._alert_repo and decision.trigger_alert_id:
                    alert = await self._alert_repo.get(decision.trigger_alert_id)
                await self._executor.execute_after_approval(decision, alert=alert)
            except Exception as exc:  # noqa: BLE001
                _log.error(
                    "human_queue_post_approval_error",
                    decision_id=str(decision_id),
                    error=str(exc),
                )
        return decision

    async def reject(self, decision_id: UUID, operator: str, note: str = "") -> Decision | None:
        """Record an operator rejection for *decision_id*."""
        return await self._update_decision(decision_id, "rejected", operator, note)

    async def _update_decision(
        self,
        decision_id: UUID,
        outcome: str,
        operator: str,
        note: str,
    ) -> Decision | None:
        decision = await self._repo.get(decision_id)
        if decision is None:
            _log.warning("human_queue_not_found", decision_id=str(decision_id))
            return None

        if decision.human_decision is not None:
            _log.warning(
                "human_queue_already_decided",
                decision_id=str(decision_id),
                existing=decision.human_decision,
            )
            return None  # D-01: already decided — do not re-trigger execute_after_approval

        now = datetime.now(UTC)
        # F-03: update_human_decision uses WHERE human_decision IS NULL — atomic.
        # rowcount=0 means either not found or already decided by a concurrent request.
        updated = await self._repo.update_human_decision(
            decision_id=decision_id,
            human_decision=outcome,
            human_operator=operator,
            human_note=note,
            approved_at=now.isoformat(),
        )
        if not updated:
            _log.warning(
                "human_queue_update_skipped",
                decision_id=str(decision_id),
                reason="not_found_or_already_decided",
            )
            return None

        result = decision.model_copy(
            update={
                "human_decision": outcome,
                "human_operator": operator,
                "human_note": note,
                "approved_at": now,
            }
        )
        _log.info(
            "human_queue_decided",
            decision_id=str(decision_id),
            outcome=outcome,
            operator=operator,
        )
        return result

    async def _expire_timeout(self) -> None:
        """Auto-reject decisions whose timeout_at has passed."""
        now = datetime.now(UTC)
        pending = await self._repo.get_pending()

        for decision in pending:
            if decision.timeout_at and decision.timeout_at <= now:
                await self._update_decision(
                    decision.decision_id,
                    "rejected",
                    operator="system",
                    note="Auto-expired: timeout reached",
                )
                _log.info(
                    "human_queue_auto_expired",
                    decision_id=str(decision.decision_id),
                )
