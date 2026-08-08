"""Unit tests for Phase 5 — Decision Engine."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from oseye.core.schema import Alert, Decision, Incident, IncidentEvent
from oseye.decision.engine import DecisionEngine, PolicyOverrides, WeightedScorer, _apply_risk_matrix
from oseye.decision.journal import DecisionJournal, _GENESIS_HASH
from oseye.decision.action_executor import ActionExecutor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_incident(
    *,
    hostname: str = "host1",
    severity: str = "high",
    alert_count: int = 3,
) -> Incident:
    now = datetime.now(UTC)
    return Incident(
        incident_id=uuid4(),
        created_at=now,
        updated_at=now,
        hostname=hostname,
        severity=severity,  # type: ignore[arg-type]
        alert_count=alert_count,
    )


def _make_alert(*, ti_triggered: bool = False, hostname: str = "host1") -> Alert:
    now = datetime.now(UTC)
    return Alert(
        alert_id=uuid4(),
        created_at=now,
        updated_at=now,
        severity="high",
        status="open",
        entity_id=hostname,
        hostname=hostname,
        trigger_event_id=uuid4(),
        title="Test alert",
        ti_triggered=ti_triggered,
    )


# ---------------------------------------------------------------------------
# WeightedScorer
# ---------------------------------------------------------------------------

class TestWeightedScorer:
    def test_all_zeros(self) -> None:
        s = WeightedScorer()
        assert s.compute(0, 0, 0, 0) == pytest.approx(0.0)

    def test_all_max(self) -> None:
        s = WeightedScorer()
        # depth_norm capped at 100 when depth >= MAX_CORRELATION_DEPTH (20)
        assert s.compute(100, 100, 100, 20) == pytest.approx(100.0)

    def test_weights(self) -> None:
        s = WeightedScorer()
        # rule=100, rest=0, depth=0 → 40.0
        assert s.compute(100, 0, 0, 0) == pytest.approx(40.0)
        # ml=100, rest=0 → 30.0
        assert s.compute(0, 100, 0, 0) == pytest.approx(30.0)
        # ti=100, rest=0 → 20.0
        assert s.compute(0, 0, 100, 0) == pytest.approx(20.0)

    def test_depth_normalisation(self) -> None:
        s = WeightedScorer()
        # depth=10 → 50% of max → 50 × 0.1 = 5.0
        assert s.compute(0, 0, 0, 10) == pytest.approx(5.0)
        # depth=30 capped to 20 → 100% → 10.0
        assert s.compute(0, 0, 0, 30) == pytest.approx(10.0)

    def test_clamped_below_zero(self) -> None:
        s = WeightedScorer()
        assert s.compute(-100, -100, -100, 0) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Risk matrix
# ---------------------------------------------------------------------------

class TestRiskMatrix:
    def test_ignore(self) -> None:
        assert _apply_risk_matrix(0) == ["IGNORE"]
        assert _apply_risk_matrix(20) == ["IGNORE"]

    def test_escalate(self) -> None:
        assert _apply_risk_matrix(21) == ["ESCALATE"]
        assert _apply_risk_matrix(40) == ["ESCALATE"]

    def test_alert_investigate(self) -> None:
        assert _apply_risk_matrix(41) == ["ALERT", "INVESTIGATE"]
        assert _apply_risk_matrix(60) == ["ALERT", "INVESTIGATE"]

    def test_alert_isolate(self) -> None:
        assert _apply_risk_matrix(61) == ["ALERT", "ISOLATE"]
        assert _apply_risk_matrix(80) == ["ALERT", "ISOLATE"]

    def test_alert_isolate_human(self) -> None:
        result = _apply_risk_matrix(81)
        assert "REQUEST_HUMAN" in result
        assert _apply_risk_matrix(100) == ["ALERT", "ISOLATE", "REQUEST_HUMAN"]


# ---------------------------------------------------------------------------
# PolicyOverrides
# ---------------------------------------------------------------------------

class TestPolicyOverrides:
    def test_whitelist_zeroes_score(self) -> None:
        p = PolicyOverrides(whitelist={"host1"})
        assert p.apply("host1", 99.0) == 0.0

    def test_denylist_maxes_score(self) -> None:
        p = PolicyOverrides(denylist={"badhost"})
        assert p.apply("badhost", 10.0) == 100.0

    def test_unaffected(self) -> None:
        p = PolicyOverrides()
        assert p.apply("other", 55.0) == 55.0

    def test_is_whitelisted(self) -> None:
        p = PolicyOverrides(whitelist={"host1"})
        assert p.is_whitelisted("host1")
        assert not p.is_whitelisted("host2")


# ---------------------------------------------------------------------------
# DecisionJournal
# ---------------------------------------------------------------------------

class TestDecisionJournal:
    def test_genesis_prev_hash(self) -> None:
        j = DecisionJournal()
        prev, _ = j.commit({"decision_id": "x", "decision_type": "ALERT"})
        assert prev == _GENESIS_HASH

    def test_chain_advances(self) -> None:
        j = DecisionJournal()
        _, h1 = j.commit({"a": "1"})
        prev2, h2 = j.commit({"a": "2"})
        assert prev2 == h1
        assert h1 != h2
        assert j.last_hash == h2

    def test_deterministic(self) -> None:
        j1 = DecisionJournal()
        j2 = DecisionJournal()
        fields = {"x": "v"}
        _, h1 = j1.commit(fields)
        _, h2 = j2.commit(fields)
        assert h1 == h2


# ---------------------------------------------------------------------------
# DecisionEngine
# ---------------------------------------------------------------------------

class TestDecisionEngine:
    @pytest.fixture()
    def engine(self) -> DecisionEngine:
        return DecisionEngine(journal=DecisionJournal(), policy_version="test-v1")

    @pytest.mark.asyncio
    async def test_produces_decision(self, engine: DecisionEngine) -> None:
        incident = _make_incident(severity="high", alert_count=5)
        decision = await engine.decide(incident)

        assert decision.entity_id == incident.hostname
        assert decision.incident_chain_id == incident.incident_id
        assert decision.policy_version == "test-v1"
        assert decision.prev_journal_hash == _GENESIS_HASH
        assert len(decision.journal_hash) == 64

    @pytest.mark.asyncio
    async def test_high_severity_not_ignored(self, engine: DecisionEngine) -> None:
        incident = _make_incident(severity="critical", alert_count=10)
        decision = await engine.decide(incident)
        assert decision.decision_type != "IGNORE"

    @pytest.mark.asyncio
    async def test_low_severity_may_ignore(self, engine: DecisionEngine) -> None:
        incident = _make_incident(severity="low", alert_count=1)
        decision = await engine.decide(incident)
        # low severity + no TI + no ML + depth 1 → score ≤ 20 → IGNORE
        assert decision.decision_type == "IGNORE"

    @pytest.mark.asyncio
    async def test_ti_triggered_boosts_score(self, engine: DecisionEngine) -> None:
        incident = _make_incident(severity="low", alert_count=1)
        alert = _make_alert(ti_triggered=True)
        decision = await engine.decide(incident, alert=alert)
        # ti_score=100 × 0.2 = 20 + rule=25 × 0.4 = 10 → total = 30+ → not IGNORE
        assert decision.decision_type != "IGNORE"
        assert decision.ti_score == 100.0

    @pytest.mark.asyncio
    async def test_whitelist_produces_ignore(self) -> None:
        overrides = PolicyOverrides(whitelist={"trusted-host"})
        engine = DecisionEngine(
            journal=DecisionJournal(), policy_overrides=overrides
        )
        incident = _make_incident(hostname="trusted-host", severity="critical", alert_count=20)
        decision = await engine.decide(incident)
        assert decision.decision_type == "IGNORE"

    @pytest.mark.asyncio
    async def test_denylist_produces_human(self) -> None:
        overrides = PolicyOverrides(denylist={"bad-host"})
        engine = DecisionEngine(
            journal=DecisionJournal(), policy_overrides=overrides
        )
        incident = _make_incident(hostname="bad-host", severity="low", alert_count=1)
        decision = await engine.decide(incident)
        assert decision.requires_human is True
        assert decision.timeout_at is not None

    @pytest.mark.asyncio
    async def test_journal_chain_across_decisions(self, engine: DecisionEngine) -> None:
        incident1 = _make_incident()
        incident2 = _make_incident()
        d1 = await engine.decide(incident1)
        d2 = await engine.decide(incident2)
        assert d2.prev_journal_hash == d1.journal_hash

    @pytest.mark.asyncio
    async def test_requires_human_sets_timeout(self) -> None:
        overrides = PolicyOverrides(denylist={"h"})
        engine = DecisionEngine(
            journal=DecisionJournal(),
            policy_overrides=overrides,
            human_timeout_secs=600,
        )
        incident = _make_incident(hostname="h")
        decision = await engine.decide(incident)
        assert decision.timeout_at is not None
        delta = decision.timeout_at - decision.created_at
        assert 590 <= delta.total_seconds() <= 610


# ---------------------------------------------------------------------------
# ActionExecutor
# ---------------------------------------------------------------------------

class TestActionExecutor:
    def _make_executor(self) -> tuple[ActionExecutor, AsyncMock]:
        bus = MagicMock()
        bus.publish = AsyncMock()
        return ActionExecutor(bus=bus), bus.publish

    def _make_decision(self, decision_type: str, requires_human: bool = False) -> Decision:
        now = datetime.now(UTC)
        return Decision(
            decision_id=uuid4(),
            created_at=now,
            decision_type=decision_type,  # type: ignore[arg-type]
            rule_score=50.0,
            ml_score=0.0,
            ti_score=0.0,
            correlation_depth=1,
            final_score=50.0,
            entity_id="host1",
            policy_version="v1",
            explanation="test",
            requires_human=requires_human,
            prev_journal_hash="0" * 64,
            journal_hash="a" * 64,
        )

    @pytest.mark.asyncio
    async def test_ignore_no_publish(self) -> None:
        executor, publish = self._make_executor()
        await executor.execute(self._make_decision("IGNORE"))
        publish.assert_not_called()

    @pytest.mark.asyncio
    async def test_alert_publishes_completed(self) -> None:
        executor, publish = self._make_executor()
        await executor.execute(self._make_decision("ALERT"))
        assert publish.call_count >= 1
        topic = publish.call_args_list[0][0][0]
        assert topic == "decisions:completed"

    @pytest.mark.asyncio
    async def test_request_human_publishes_pending(self) -> None:
        executor, publish = self._make_executor()
        await executor.execute(self._make_decision("REQUEST_HUMAN", requires_human=True))
        assert publish.call_count >= 1
        topic = publish.call_args_list[0][0][0]
        assert topic == "decisions:pending"

    @pytest.mark.asyncio
    async def test_isolate_emits_policy_push(self) -> None:
        executor, publish = self._make_executor()
        await executor.execute(self._make_decision("ISOLATE"))
        topics = [call[0][0] for call in publish.call_args_list]
        assert "decisions:completed" in topics
        assert any("policy:push:" in t for t in topics)

    @pytest.mark.asyncio
    async def test_investigate_emits_forensics(self) -> None:
        executor, publish = self._make_executor()
        await executor.execute(self._make_decision("INVESTIGATE"))
        topics = [call[0][0] for call in publish.call_args_list]
        assert "forensics:snapshot:request" in topics
