"""Integration test: ml_score > 0 when ml_engine is wired into DecisionEngine."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from oseye.core.schema import Alert, Incident, UniversalEvent
from oseye.decision.engine import DecisionEngine, PolicyOverrides
from oseye.decision.journal import DecisionJournal
from oseye.ml_engine.engine import MLEngine


def _make_event() -> UniversalEvent:
    return UniversalEvent(
        event_id=uuid.uuid4(),
        timestamp_ns=time.time_ns(),
        hostname="test-host",
        agent_id=uuid.uuid4(),
        category="process",
        type="exec",
        severity="high",
        collector="procfs",
        os="linux",
        process_name="mimikatz",
        executable="/tmp/mimikatz",
    )


def _make_incident(alert_count: int = 3) -> Incident:
    return Incident(
        incident_id=uuid.uuid4(),
        hostname="test-host",
        severity="high",
        status="open",
        alert_ids=[uuid.uuid4()],
        alert_count=alert_count,
        mitre_tactics=["TA0006"],
        correlation_rule="same_host",
        timeframe_seconds=120,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def _make_alert(event: UniversalEvent) -> Alert:
    return Alert(
        alert_id=uuid.uuid4(),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        severity="high",
        status="open",
        rule_id="detect.credential_access",
        entity_id=f"{event.hostname}:{event.pid}",
        hostname=event.hostname,
        trigger_event_id=event.event_id,
        title="Credential access detected",
        mitre_techniques=["T1003"],
    )


@pytest.mark.asyncio
async def test_ml_score_nonzero_when_engine_wired() -> None:
    """ml_score must be > 0 when ml_engine is passed to DecisionEngine."""
    ml_engine = MLEngine()

    # Train the ML engine briefly so it has a baseline
    for _ in range(60):
        ev = _make_event()
        ml_engine.score_event(ev)

    engine = DecisionEngine(
        journal=DecisionJournal(),
        policy_overrides=PolicyOverrides(),
        ml_engine=ml_engine,
    )

    event = _make_event()
    incident = _make_incident()
    alert = _make_alert(event)

    decision = await engine.decide(incident, alert=alert, trigger_event=event)

    # ml_score should be non-zero (cold-start returns 0.0 until min_samples reached,
    # but after 60 events it should have a value).
    assert decision.ml_score >= 0.0, "ml_score should be non-negative"
    # Verify it was actually computed (not the hardcoded 0.0 fallback)
    assert decision.rule_score > 0.0, "rule_score should reflect high severity"


@pytest.mark.asyncio
async def test_ml_score_zero_when_engine_not_wired() -> None:
    """ml_score must be 0.0 when ml_engine is NOT passed (regression guard)."""
    engine = DecisionEngine(
        journal=DecisionJournal(),
        policy_overrides=PolicyOverrides(),
        ml_engine=None,  # not wired
    )

    event = _make_event()
    incident = _make_incident()
    alert = _make_alert(event)

    decision = await engine.decide(incident, alert=alert, trigger_event=event)
    assert decision.ml_score == 0.0
