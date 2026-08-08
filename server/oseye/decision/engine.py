"""Decision Engine — Phase 5.

Consumes a correlated Incident, computes a weighted risk score, applies the
risk matrix, checks policy overrides, and produces a Decision.

Score formula:
    final = rule×0.4 + ml×0.3 + ti×0.2 + correlation_depth_norm×0.1

Risk matrix (final ∈ [0, 100]):
    0–20  → IGNORE
    21–40 → ESCALATE
    41–60 → ALERT + INVESTIGATE
    61–80 → ALERT + ISOLATE
    81–100 → ALERT + ISOLATE + REQUEST_HUMAN
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal
from uuid import uuid4

from oseye.core.observability import get_logger
from oseye.core.schema import Decision

if TYPE_CHECKING:
    from oseye.core.schema import Alert, Incident
    from oseye.decision.journal import DecisionJournal

_log = get_logger(__name__)

DecisionType = Literal[
    "ALERT", "IGNORE", "ESCALATE", "INVESTIGATE",
    "ISOLATE", "REQUEST_HUMAN", "COLLECT_MORE", "NOTIFY",
]

_SEVERITY_SCORE: dict[str, float] = {
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}

_MAX_CORRELATION_DEPTH = 20


class PolicyOverrides:
    """Simple allowlist/denylist checked before risk matrix.

    Entries are entity_id strings. Whitelisted entities always → IGNORE.
    Denylisted entities bump the final score to 100 → REQUEST_HUMAN.
    """

    def __init__(
        self,
        whitelist: set[str] | None = None,
        denylist: set[str] | None = None,
    ) -> None:
        self._whitelist: set[str] = whitelist or set()
        self._denylist: set[str] = denylist or set()

    def apply(self, entity_id: str, score: float) -> float:
        if entity_id in self._whitelist:
            return 0.0
        if entity_id in self._denylist:
            return 100.0
        return score

    def is_whitelisted(self, entity_id: str) -> bool:
        return entity_id in self._whitelist


class WeightedScorer:
    """Combines four signal scores into a single [0, 100] final score."""

    _W_RULE = 0.4
    _W_ML = 0.3
    _W_TI = 0.2
    _W_DEPTH = 0.1

    def compute(
        self,
        rule_score: float,
        ml_score: float,
        ti_score: float,
        correlation_depth: int,
    ) -> float:
        depth_norm = min(correlation_depth / _MAX_CORRELATION_DEPTH, 1.0) * 100.0
        raw = (
            rule_score * self._W_RULE
            + ml_score * self._W_ML
            + ti_score * self._W_TI
            + depth_norm * self._W_DEPTH
        )
        return max(0.0, min(100.0, raw))


def _apply_risk_matrix(score: float) -> list[DecisionType]:
    if score <= 20:
        return ["IGNORE"]
    if score <= 40:
        return ["ESCALATE"]
    if score <= 60:
        return ["ALERT", "INVESTIGATE"]
    if score <= 80:
        return ["ALERT", "ISOLATE"]
    return ["ALERT", "ISOLATE", "REQUEST_HUMAN"]


class DecisionEngine:
    """Produces Decision objects from correlated Incidents.

    Parameters
    ----------
    journal:            DecisionJournal for hash chaining.
    policy_overrides:   Optional PolicyOverrides instance.
    human_timeout_secs: Seconds before a REQUEST_HUMAN decision auto-expires.
    policy_version:     String tag embedded in every Decision for audit.
    """

    def __init__(
        self,
        journal: DecisionJournal,
        policy_overrides: PolicyOverrides | None = None,
        human_timeout_secs: int = 3600,
        policy_version: str = "v1.0",
    ) -> None:
        self._journal = journal
        self._overrides = policy_overrides or PolicyOverrides()
        self._human_timeout_secs = human_timeout_secs
        self._policy_version = policy_version
        self._scorer = WeightedScorer()
        self._lock = asyncio.Lock()

    async def decide(
        self,
        incident: Incident,
        alert: Alert | None = None,
    ) -> Decision:
        """Produce a Decision for the given incident.

        The journal lock is held during hash computation to ensure serial
        ordering of chain entries even under concurrent correlated incidents.
        """
        # Derive signal scores from incident context
        rule_score = _SEVERITY_SCORE.get(incident.severity, 50.0)
        ml_score = 0.0  # ML engine not yet wired; default neutral
        ti_score = 100.0 if (alert and alert.ti_triggered) else 0.0
        correlation_depth = incident.alert_count

        final_score = self._scorer.compute(rule_score, ml_score, ti_score, correlation_depth)
        final_score = self._overrides.apply(incident.hostname, final_score)

        decision_types = _apply_risk_matrix(final_score)
        primary_type: DecisionType = decision_types[0]
        requires_human = "REQUEST_HUMAN" in decision_types

        explanation = _build_explanation(
            decision_types, rule_score, ml_score, ti_score, correlation_depth, final_score
        )

        now = datetime.now(UTC)
        timeout_at = (now + timedelta(seconds=self._human_timeout_secs)) if requires_human else None

        decision_fields: dict[str, object] = {
            "decision_id": str(uuid4()),
            "created_at": now.isoformat(),
            "decision_type": primary_type,
            "rule_score": rule_score,
            "ml_score": ml_score,
            "ti_score": ti_score,
            "correlation_depth": correlation_depth,
            "final_score": final_score,
            "entity_id": incident.hostname,
            "trigger_alert_id": str(alert.alert_id) if alert else None,
            "incident_chain_id": str(incident.incident_id),
            "policy_version": self._policy_version,
            "explanation": explanation,
        }

        async with self._lock:
            prev_hash, journal_hash = self._journal.commit(decision_fields)

        # Store prev_hash on the decision so DecisionWorker can rollback if
        # persistence fails (F-01: journal must not permanently diverge from DB).
        decision = Decision(
            decision_id=decision_fields["decision_id"],  # type: ignore[arg-type]
            created_at=now,
            decision_type=primary_type,
            rule_score=rule_score,
            ml_score=ml_score,
            ti_score=ti_score,
            correlation_depth=correlation_depth,
            final_score=final_score,
            entity_id=incident.hostname,
            trigger_alert_id=alert.alert_id if alert else None,
            incident_chain_id=incident.incident_id,
            related_event_ids=list(alert.related_event_ids) if alert else [],
            policy_version=self._policy_version,
            explanation=explanation,
            requires_human=requires_human,
            timeout_at=timeout_at,
            prev_journal_hash=prev_hash,
            journal_hash=journal_hash,
        )

        _log.info(
            "decision_produced",
            decision_id=str(decision.decision_id),
            decision_type=primary_type,
            final_score=round(final_score, 2),
            requires_human=requires_human,
            incident_id=str(incident.incident_id),
            entity_id=incident.hostname,
        )

        return decision


    async def rollback_journal(self, prev_hash: str) -> None:
        """Revert the journal to *prev_hash* after a failed persist.

        Must be called when decision_repo.create() fails so that the in-memory
        journal stays consistent with what is actually in the database.
        """
        async with self._lock:
            self._journal.rollback(prev_hash)


def _build_explanation(
    decision_types: list[DecisionType],
    rule_score: float,
    ml_score: float,
    ti_score: float,
    correlation_depth: int,
    final_score: float,
) -> str:
    actions = "+".join(decision_types)
    return (
        f"Actions: {actions}. "
        f"Score: {final_score:.1f}/100 "
        f"(rule={rule_score:.0f}×0.4, ml={ml_score:.0f}×0.3, "
        f"ti={ti_score:.0f}×0.2, depth={correlation_depth}×0.1). "
    )
