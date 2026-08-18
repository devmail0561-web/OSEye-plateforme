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
    from oseye.core.schema import Alert, Incident, UniversalEvent
    from oseye.decision.journal import DecisionJournal
    from oseye.ml_engine.engine import MLEngine

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

    def __init__(
        self,
        w_rule: float = 0.4,
        w_ml: float = 0.3,
        w_ti: float = 0.2,
        w_depth: float = 0.1,
    ) -> None:
        self._w_rule = w_rule
        self._w_ml = w_ml
        self._w_ti = w_ti
        self._w_depth = w_depth
        total = w_rule + w_ml + w_ti + w_depth
        if not all(0.0 <= w <= 1.0 for w in [w_rule, w_ml, w_ti, w_depth]):
            raise ValueError("All decision weights must be in [0.0, 1.0]")
        if abs(total - 1.0) > 0.001:
            raise ValueError(f"Decision weights must sum to 1.0, got {total:.4f}")

    def compute(
        self,
        rule_score: float,
        ml_score: float,
        ti_score: float,
        correlation_depth: int,
    ) -> float:
        depth_norm = min(correlation_depth / _MAX_CORRELATION_DEPTH, 1.0) * 100.0
        raw = (
            rule_score * self._w_rule
            + ml_score * self._w_ml
            + ti_score * self._w_ti
            + depth_norm * self._w_depth
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
        ml_engine: MLEngine | None = None,
        weight_rule: float = 0.4,
        weight_ml: float = 0.3,
        weight_ti: float = 0.2,
        weight_depth: float = 0.1,
        redis_url: str | None = None,
    ) -> None:
        self._journal = journal
        self._overrides = policy_overrides or PolicyOverrides()
        self._human_timeout_secs = human_timeout_secs
        self._policy_version = policy_version
        self._scorer = WeightedScorer(
            w_rule=weight_rule,
            w_ml=weight_ml,
            w_ti=weight_ti,
            w_depth=weight_depth,
        )
        self._ml_engine = ml_engine
        self._lock = asyncio.Lock()
        self._redis_url = redis_url
        self._leader_key = "oseye:decision:leader"
        self._leader_ttl = 30  # secondes — renouvellement toutes les 15s

    async def _is_leader(self) -> bool:
        """Retourne True si cette instance est le leader du journal BLAKE3.

        En mode single-server (redis_url non fourni), retourne toujours True.
        En mode distribué, utilise Redis SETNX pour élire un leader unique.
        Fail-open : si Redis est indisponible, chaque serveur agit comme leader.
        """
        if not self._redis_url:
            return True  # Single-server : toujours leader
        try:
            import socket

            import redis.asyncio as _redis
            server_id = f"{socket.gethostname()}:{id(self)}"
            async with _redis.from_url(self._redis_url) as rc:
                # NX=True : n'écrit que si absent. EX=TTL.
                result = await rc.set(self._leader_key, server_id, nx=True, ex=self._leader_ttl)
                if result:
                    return True  # On vient de devenir leader
                # Vérifier si on est déjà leader
                current = await rc.get(self._leader_key)
                current_val = current.decode() if isinstance(current, bytes) else current
                if current and current_val == server_id:
                    await rc.expire(self._leader_key, self._leader_ttl)  # Renouveler
                    return True
                return False
        except Exception as exc:
            _log.warning("decision_leader_check_failed", error=str(exc))
            return True  # Fail-open : si Redis down, chaque serveur agit comme leader

    async def decide(
        self,
        incident: Incident,
        alert: Alert | None = None,
        trigger_event: UniversalEvent | None = None,
    ) -> Decision:
        """Produce a Decision for the given incident.

        The journal lock is held during hash computation to ensure serial
        ordering of chain entries even under concurrent correlated incidents.

        .. warning:: CALLER MUST NOT CALL decide() CONCURRENTLY without an
            external asyncio.Lock covering both decide() AND the subsequent DB
            persist.  The internal ``self._lock`` protects only journal.commit().
            If two callers each call decide() and the first caller's DB persist
            fails, rollback_journal() reverts the chain to prev_hash — but the
            second caller's journal entry was already committed on top of the
            first one's hash, so the chain becomes inconsistent.
            To prevent this, DecisionWorker (or any caller handling multiple
            concurrent incidents) MUST hold a single external lock for the full
            decide() + decision_repo.create() + (rollback_journal on failure)
            cycle.  See rollback_journal() for the recovery path.

        Parameters
        ----------
        incident:      Correlated incident to decide on.
        alert:         Optional trigger alert (used for TI and MITRE signals).
        trigger_event: Optional normalised event that triggered the alert.
                       When provided, the ML engine scores it to produce
                       ml_score; without it, ml_score falls back to 0.
        """
        # Derive signal scores from incident context
        rule_score = _SEVERITY_SCORE.get(incident.severity, 50.0)
        # D-08: warn when an unknown severity falls through to the default 50.0
        if incident.severity not in _SEVERITY_SCORE:
            _log.warning("decision_engine: unknown severity", severity=incident.severity)
        if self._ml_engine is not None and trigger_event is not None:
            # ML-R-01: prefer score_event_readonly (no training side-effect); fall back
            # to score_event for older MLEngine versions that lack the method.
            _score_fn = getattr(
                self._ml_engine, "score_event_readonly", None
            ) or self._ml_engine.score_event
            ml_score = _score_fn(trigger_event)
            ml_score = max(0.0, min(100.0, ml_score))
        else:
            ml_score = 0.0
        ti_score = 100.0 if (alert and alert.ti_triggered) else 0.0
        correlation_depth = incident.alert_count

        final_score = self._scorer.compute(rule_score, ml_score, ti_score, correlation_depth)
        # Vérifie que le hostname est l'entité réelle de l'incident (non modifiable)
        entity_id = incident.entity_id if hasattr(incident, "entity_id") else incident.hostname
        # TODO: valider entity_id contre le CN TLS de l'agent (voir TODO H-13)
        final_score = self._overrides.apply(entity_id, final_score)

        decision_types = _apply_risk_matrix(final_score)
        primary_type: DecisionType = decision_types[0]
        requires_human = "REQUEST_HUMAN" in decision_types

        explanation = _build_explanation(
            decision_types, rule_score, ml_score, ti_score, correlation_depth, final_score,
            w_rule=self._scorer._w_rule,
            w_ml=self._scorer._w_ml,
            w_ti=self._scorer._w_ti,
            w_depth=self._scorer._w_depth,
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
            "entity_id": entity_id,
            "trigger_alert_id": str(alert.alert_id) if alert else None,
            "incident_chain_id": str(incident.incident_id),
            "policy_version": self._policy_version,
            "explanation": explanation,
        }

        is_leader = await self._is_leader()
        if is_leader:
            async with self._lock:
                prev_hash, journal_hash = self._journal.commit(decision_fields)
                try:
                    # DE-02: Decision construction is within the lock so that a
                    # rollback on failure stays serialised with the commit.
                    decision = Decision(
                        decision_id=decision_fields["decision_id"],  # type: ignore[arg-type]
                        created_at=now,
                        decision_type=primary_type,
                        decision_types=list(decision_types),
                        rule_score=rule_score,
                        ml_score=ml_score,
                        ti_score=ti_score,
                        correlation_depth=correlation_depth,
                        final_score=final_score,
                        entity_id=entity_id,
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
                except Exception:
                    self._journal.rollback(prev_hash)
                    raise
        else:
            # Follower : persiste la décision sans journal BLAKE3.
            # Le journal sera reconstituable depuis le leader.
            _log.debug(
                "decision_follower_skip_journal",
                decision_id=str(decision_fields["decision_id"]),
            )
            decision = Decision(
                decision_id=decision_fields["decision_id"],  # type: ignore[arg-type]
                created_at=now,
                decision_type=primary_type,
                decision_types=list(decision_types),
                rule_score=rule_score,
                ml_score=ml_score,
                ti_score=ti_score,
                correlation_depth=correlation_depth,
                final_score=final_score,
                entity_id=entity_id,
                trigger_alert_id=alert.alert_id if alert else None,
                incident_chain_id=incident.incident_id,
                related_event_ids=list(alert.related_event_ids) if alert else [],
                policy_version=self._policy_version,
                explanation=explanation,
                requires_human=requires_human,
                timeout_at=timeout_at,
                prev_journal_hash=None,
                journal_hash=None,
            )

        _log.info(
            "decision_produced",
            decision_id=str(decision.decision_id),
            decision_type=primary_type,
            final_score=round(final_score, 2),
            requires_human=requires_human,
            incident_id=str(incident.incident_id),
            entity_id=entity_id,
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
    w_rule: float = 0.4,
    w_ml: float = 0.3,
    w_ti: float = 0.2,
    w_depth: float = 0.1,
) -> str:
    actions = "+".join(decision_types)
    return (
        f"Actions: {actions}. "
        f"Score: {final_score:.1f}/100 "
        f"(rule={rule_score:.0f}×{w_rule}, ml={ml_score:.0f}×{w_ml}, "
        f"ti={ti_score:.0f}×{w_ti}, depth={correlation_depth}×{w_depth}). "
    )
