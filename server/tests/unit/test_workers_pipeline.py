"""Unit tests for CorrelationWorker, DecisionWorker, and TIWorker.

All repositories and engines are mocked — no real DB or network calls.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID, uuid4

import pytest

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-key-for-pytest-32chars")

from oseye.bus.memory_bus import InMemoryEventBus  # noqa: E402
from oseye.core.schema import Alert, Decision, Incident  # noqa: E402
from oseye.threat_intel.models import AggregatedTIReport  # noqa: E402
from oseye.workers.correlation_worker import CorrelationWorker  # noqa: E402
from oseye.workers.decision_worker import DecisionWorker  # noqa: E402
from oseye.workers.ti_worker import TIWorker  # noqa: E402

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(UTC)


def _make_alert(
    *,
    alert_id: UUID | None = None,
    severity: str = "high",
    incident_chain_id: UUID | None = None,
) -> Alert:
    return Alert(
        alert_id=alert_id or uuid4(),
        created_at=_NOW,
        updated_at=_NOW,
        severity=severity,  # type: ignore[arg-type]
        status="open",
        entity_id="host-a::proc",
        hostname="host-a",
        trigger_event_id=uuid4(),
        title="Test Alert",
        incident_chain_id=incident_chain_id,
    )


def _make_incident(
    *,
    incident_id: UUID | None = None,
    severity: str = "high",
    alert_count: int = 1,
) -> Incident:
    return Incident(
        incident_id=incident_id or uuid4(),
        hostname="host-a",
        severity=severity,  # type: ignore[arg-type]
        alert_count=alert_count,
    )


def _make_decision(*, incident: Incident, alert: Alert | None = None) -> Decision:
    return Decision(
        decision_id=uuid4(),
        created_at=_NOW,
        decision_type="ALERT",
        rule_score=0.5,
        ml_score=0.5,
        ti_score=0.0,
        correlation_depth=1,
        final_score=0.5,
        entity_id=incident.hostname,
        incident_chain_id=incident.incident_id,
        trigger_alert_id=alert.alert_id if alert else None,
        policy_version="test-1.0",
        explanation="unit test",
        prev_journal_hash="a" * 64,
        journal_hash="b" * 64,
    )


async def _collect_published(
    bus: InMemoryEventBus, topic: str, count: int, timeout: float = 2.0
) -> list[dict]:  # type: ignore[type-arg]
    """Subscribe and collect up to *count* messages from *topic*."""
    results: list[dict] = []  # type: ignore[type-arg]
    gen = await bus.subscribe(topic)

    async def _read() -> None:
        async for msg in gen:
            results.append(json.loads(msg))
            if len(results) >= count:
                break

    try:
        await asyncio.wait_for(_read(), timeout=timeout)
    except TimeoutError:
        pass
    return results


def _make_ti_report(
    indicator: str = "1.2.3.4",
    *,
    malicious: bool = False,
    max_score: float = 0.0,
    tags: list[str] | None = None,
) -> AggregatedTIReport:
    return AggregatedTIReport(
        indicator=indicator,
        indicator_type="ip",
        max_score=max_score,
        malicious=malicious,
        tags=tags or [],
        queried_at=_NOW,
    )


# ===========================================================================
# CorrelationWorker tests
# ===========================================================================


@pytest.mark.asyncio
async def test_correlation_calls_engine_process_alert() -> None:
    """Worker calls engine.process_alert with the loaded alert."""
    bus = InMemoryEventBus()
    alert = _make_alert()
    incident = _make_incident()

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)
    alert_repo.update = AsyncMock()

    engine = MagicMock()
    engine.process_alert = AsyncMock(return_value=incident)
    engine.get_incident = AsyncMock(return_value=None)

    stop = asyncio.Event()
    worker = CorrelationWorker(bus=bus, engine=engine, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps({"alert_id": str(alert.alert_id)}).encode()
    await bus.publish("alerts:created", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    engine.process_alert.assert_awaited_once_with(alert)


@pytest.mark.asyncio
async def test_correlation_publishes_on_new_incident() -> None:
    """Worker publishes analysis:correlated when alert_count == 1 (new incident)."""
    bus = InMemoryEventBus()
    alert = _make_alert()
    incident = _make_incident(alert_count=1)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)
    alert_repo.update = AsyncMock()

    engine = MagicMock()
    engine.process_alert = AsyncMock(return_value=incident)
    engine.get_incident = AsyncMock(return_value=None)

    stop = asyncio.Event()
    worker = CorrelationWorker(bus=bus, engine=engine, alert_repo=alert_repo, stop_event=stop)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    collector_task = asyncio.create_task(
        _collect_published(bus, "analysis:correlated", count=1, timeout=2.0)
    )
    await asyncio.sleep(0.02)

    payload = json.dumps({"alert_id": str(alert.alert_id)}).encode()
    await bus.publish("alerts:created", payload)

    messages = await collector_task
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    assert len(messages) == 1
    assert messages[0]["incident_id"] == str(incident.incident_id)
    assert messages[0]["trigger_alert_id"] == str(alert.alert_id)


@pytest.mark.asyncio
async def test_correlation_publishes_on_severity_escalation() -> None:
    """Worker publishes when severity escalates (F-03 fix)."""
    bus = InMemoryEventBus()
    alert_id = uuid4()
    inc_id = uuid4()
    alert = _make_alert(alert_id=alert_id, incident_chain_id=inc_id)

    existing_incident = _make_incident(incident_id=inc_id, severity="low", alert_count=3)
    escalated_incident = _make_incident(incident_id=inc_id, severity="high", alert_count=3)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)
    alert_repo.update = AsyncMock()

    engine = MagicMock()
    engine.process_alert = AsyncMock(return_value=escalated_incident)
    engine.get_incident = AsyncMock(return_value=existing_incident)

    stop = asyncio.Event()
    worker = CorrelationWorker(bus=bus, engine=engine, alert_repo=alert_repo, stop_event=stop)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    collector_task = asyncio.create_task(
        _collect_published(bus, "analysis:correlated", count=1, timeout=2.0)
    )
    await asyncio.sleep(0.02)

    payload = json.dumps({"alert_id": str(alert_id)}).encode()
    await bus.publish("alerts:created", payload)

    messages = await collector_task
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    assert len(messages) == 1
    assert messages[0]["incident_id"] == str(inc_id)


@pytest.mark.asyncio
async def test_correlation_no_publish_same_severity_multi_alert() -> None:
    """Worker does NOT publish when severity is unchanged and alert_count > 1."""
    bus = InMemoryEventBus()
    alert_id = uuid4()
    inc_id = uuid4()
    alert = _make_alert(alert_id=alert_id, incident_chain_id=inc_id)

    existing_incident = _make_incident(incident_id=inc_id, severity="high", alert_count=2)
    same_incident = _make_incident(incident_id=inc_id, severity="high", alert_count=3)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)
    alert_repo.update = AsyncMock()

    engine = MagicMock()
    engine.process_alert = AsyncMock(return_value=same_incident)
    engine.get_incident = AsyncMock(return_value=existing_incident)

    stop = asyncio.Event()
    worker = CorrelationWorker(bus=bus, engine=engine, alert_repo=alert_repo, stop_event=stop)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    collector_task = asyncio.create_task(
        _collect_published(bus, "analysis:correlated", count=1, timeout=0.3)
    )
    await asyncio.sleep(0.02)

    payload = json.dumps({"alert_id": str(alert_id)}).encode()
    await bus.publish("alerts:created", payload)

    messages = await collector_task  # should time out with 0 messages
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    assert messages == []


@pytest.mark.asyncio
async def test_correlation_invalid_json_no_crash() -> None:
    """Worker handles unparseable messages without crashing."""
    bus = InMemoryEventBus()
    alert_repo = MagicMock()
    engine = MagicMock()

    stop = asyncio.Event()
    worker = CorrelationWorker(bus=bus, engine=engine, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    await bus.publish("alerts:created", b"NOT_VALID_JSON{{{{")
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    # Worker survived — no crash
    engine.process_alert.assert_not_called()


@pytest.mark.asyncio
async def test_correlation_alert_not_found_no_crash() -> None:
    """Worker handles alert not found in DB without crashing."""
    bus = InMemoryEventBus()

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=None)

    engine = MagicMock()
    engine.process_alert = AsyncMock()

    stop = asyncio.Event()
    worker = CorrelationWorker(bus=bus, engine=engine, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps({"alert_id": str(uuid4())}).encode()
    await bus.publish("alerts:created", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    engine.process_alert.assert_not_called()


@pytest.mark.asyncio
async def test_correlation_alert_repo_raises_no_crash() -> None:
    """Worker handles a repo exception when loading alert without crashing."""
    bus = InMemoryEventBus()

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(side_effect=RuntimeError("DB down"))

    engine = MagicMock()
    engine.process_alert = AsyncMock()

    stop = asyncio.Event()
    worker = CorrelationWorker(bus=bus, engine=engine, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps({"alert_id": str(uuid4())}).encode()
    await bus.publish("alerts:created", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    engine.process_alert.assert_not_called()


# ===========================================================================
# DecisionWorker tests
# ===========================================================================


def _make_decision_worker(
    bus: InMemoryEventBus,
    *,
    engine: MagicMock | None = None,
    decision_repo: MagicMock | None = None,
    incident_repo: MagicMock | None = None,
    alert_repo: MagicMock | None = None,
    action_executor: MagicMock | None = None,
    event_repo: MagicMock | None = None,
    stop: asyncio.Event | None = None,
) -> tuple[DecisionWorker, asyncio.Event]:
    stop = stop or asyncio.Event()
    return (
        DecisionWorker(
            bus=bus,
            engine=engine or MagicMock(),
            decision_repo=decision_repo or MagicMock(),
            incident_repo=incident_repo or MagicMock(),
            alert_repo=alert_repo or MagicMock(),
            action_executor=action_executor or MagicMock(),
            event_repo=event_repo,
            stop_event=stop,
        ),
        stop,
    )


@pytest.mark.asyncio
async def test_decision_loads_incident_and_alert() -> None:
    """Worker loads incident + trigger alert, calls engine.decide."""
    bus = InMemoryEventBus()
    alert = _make_alert()
    incident = _make_incident()
    decision = _make_decision(incident=incident, alert=alert)

    incident_repo = MagicMock()
    incident_repo.get = AsyncMock(return_value=incident)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)

    engine = MagicMock()
    engine.decide = AsyncMock(return_value=decision)
    engine.rollback_journal = AsyncMock()

    decision_repo = MagicMock()
    decision_repo.create = AsyncMock()

    action_executor = MagicMock()
    action_executor.execute = AsyncMock()

    stop = asyncio.Event()
    worker = DecisionWorker(
        bus=bus,
        engine=engine,
        decision_repo=decision_repo,
        incident_repo=incident_repo,
        alert_repo=alert_repo,
        action_executor=action_executor,
        stop_event=stop,
    )

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps(
        {"incident_id": str(incident.incident_id), "trigger_alert_id": str(alert.alert_id)}
    ).encode()
    await bus.publish("analysis:correlated", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    incident_repo.get.assert_awaited_once_with(incident.incident_id)
    alert_repo.get.assert_awaited_once_with(alert.alert_id)
    engine.decide.assert_awaited_once()


@pytest.mark.asyncio
async def test_decision_persists_and_executes() -> None:
    """Worker persists decision then calls action_executor.execute."""
    bus = InMemoryEventBus()
    alert = _make_alert()
    incident = _make_incident()
    decision = _make_decision(incident=incident, alert=alert)

    incident_repo = MagicMock()
    incident_repo.get = AsyncMock(return_value=incident)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)

    engine = MagicMock()
    engine.decide = AsyncMock(return_value=decision)
    engine.rollback_journal = AsyncMock()

    decision_repo = MagicMock()
    decision_repo.create = AsyncMock()

    action_executor = MagicMock()
    action_executor.execute = AsyncMock()

    stop = asyncio.Event()
    worker = DecisionWorker(
        bus=bus,
        engine=engine,
        decision_repo=decision_repo,
        incident_repo=incident_repo,
        alert_repo=alert_repo,
        action_executor=action_executor,
        stop_event=stop,
    )

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps(
        {"incident_id": str(incident.incident_id), "trigger_alert_id": str(alert.alert_id)}
    ).encode()
    await bus.publish("analysis:correlated", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    decision_repo.create.assert_awaited_once_with(decision)
    action_executor.execute.assert_awaited_once_with(decision)


@pytest.mark.asyncio
async def test_decision_rollback_journal_on_persist_failure() -> None:
    """Worker rolls back journal when decision_repo.create() raises (F-01)."""
    bus = InMemoryEventBus()
    alert = _make_alert()
    incident = _make_incident()
    decision = _make_decision(incident=incident, alert=alert)

    incident_repo = MagicMock()
    incident_repo.get = AsyncMock(return_value=incident)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)

    engine = MagicMock()
    engine.decide = AsyncMock(return_value=decision)
    engine.rollback_journal = AsyncMock()

    decision_repo = MagicMock()
    decision_repo.create = AsyncMock(side_effect=RuntimeError("DB write failed"))

    action_executor = MagicMock()
    action_executor.execute = AsyncMock()

    stop = asyncio.Event()
    worker = DecisionWorker(
        bus=bus,
        engine=engine,
        decision_repo=decision_repo,
        incident_repo=incident_repo,
        alert_repo=alert_repo,
        action_executor=action_executor,
        stop_event=stop,
    )

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps(
        {"incident_id": str(incident.incident_id), "trigger_alert_id": str(alert.alert_id)}
    ).encode()
    await bus.publish("analysis:correlated", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    engine.rollback_journal.assert_awaited_once_with(decision.prev_journal_hash)
    action_executor.execute.assert_not_called()


@pytest.mark.asyncio
async def test_decision_incident_not_found_no_crash() -> None:
    """Worker handles missing incident gracefully."""
    bus = InMemoryEventBus()

    incident_repo = MagicMock()
    incident_repo.get = AsyncMock(return_value=None)

    engine = MagicMock()
    engine.decide = AsyncMock()

    stop = asyncio.Event()
    worker, stop = _make_decision_worker(
        bus, engine=engine, incident_repo=incident_repo, stop=stop
    )

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps({"incident_id": str(uuid4())}).encode()
    await bus.publish("analysis:correlated", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    engine.decide.assert_not_called()


@pytest.mark.asyncio
async def test_decision_trigger_alert_id_null_no_crash() -> None:
    """Worker handles payload with trigger_alert_id: null without crash (F-06)."""
    bus = InMemoryEventBus()
    incident = _make_incident()
    decision = _make_decision(incident=incident)

    incident_repo = MagicMock()
    incident_repo.get = AsyncMock(return_value=incident)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock()

    engine = MagicMock()
    engine.decide = AsyncMock(return_value=decision)
    engine.rollback_journal = AsyncMock()

    decision_repo = MagicMock()
    decision_repo.create = AsyncMock()

    action_executor = MagicMock()
    action_executor.execute = AsyncMock()

    stop = asyncio.Event()
    worker = DecisionWorker(
        bus=bus,
        engine=engine,
        decision_repo=decision_repo,
        incident_repo=incident_repo,
        alert_repo=alert_repo,
        action_executor=action_executor,
        stop_event=stop,
    )

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    # JSON null for trigger_alert_id
    payload = json.dumps(
        {"incident_id": str(incident.incident_id), "trigger_alert_id": None}
    ).encode()
    await bus.publish("analysis:correlated", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    # alert_repo.get should NOT have been called (no valid alert id)
    alert_repo.get.assert_not_called()
    engine.decide.assert_awaited_once()


@pytest.mark.asyncio
async def test_decision_invalid_json_no_crash() -> None:
    """Worker skips bad JSON without crashing."""
    bus = InMemoryEventBus()
    engine = MagicMock()
    engine.decide = AsyncMock()

    stop = asyncio.Event()
    worker, stop = _make_decision_worker(bus, engine=engine, stop=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    await bus.publish("analysis:correlated", b"GARBAGE")
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    engine.decide.assert_not_called()


# ===========================================================================
# TIWorker tests
# ===========================================================================


@pytest.mark.asyncio
async def test_ti_worker_publishes_enriched() -> None:
    """TIWorker publishes alerts:enriched with ti_score and tags."""
    bus = InMemoryEventBus()
    alert_id = uuid4()
    report = _make_ti_report("1.2.3.4", malicious=False, max_score=42.0, tags=["scanner"])

    ti_client = MagicMock()
    ti_client.lookup = AsyncMock(return_value=report)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock()
    alert_repo.update = AsyncMock()

    stop = asyncio.Event()
    worker = TIWorker(bus=bus, ti_client=ti_client, alert_repo=alert_repo, stop_event=stop)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    collector_task = asyncio.create_task(
        _collect_published(bus, "alerts:enriched", count=1, timeout=2.0)
    )
    await asyncio.sleep(0.02)

    payload = json.dumps(
        {"alert_id": str(alert_id), "indicators": {"ips": ["1.2.3.4"], "hashes": []}}
    ).encode()
    await bus.publish("alerts:enrichment", payload)

    messages = await collector_task
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    assert len(messages) == 1
    msg = messages[0]
    assert msg["alert_id"] == str(alert_id)
    assert msg["ti_score"] == pytest.approx(42.0)
    assert "scanner" in msg["tags"]
    assert msg["malicious"] is False


@pytest.mark.asyncio
async def test_ti_worker_sets_ti_triggered_when_malicious() -> None:
    """TIWorker sets alert.ti_triggered = True in DB when malicious."""
    bus = InMemoryEventBus()
    alert_id = uuid4()
    alert = _make_alert(alert_id=alert_id)
    report = _make_ti_report("bad-hash", malicious=True, max_score=95.0, tags=["malware"])

    ti_client = MagicMock()
    ti_client.lookup = AsyncMock(return_value=report)

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(return_value=alert)
    alert_repo.update = AsyncMock()

    stop = asyncio.Event()
    worker = TIWorker(bus=bus, ti_client=ti_client, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps(
        {"alert_id": str(alert_id), "indicators": {"ips": [], "hashes": ["bad-hash"]}}
    ).encode()
    await bus.publish("alerts:enrichment", payload)
    await asyncio.sleep(0.1)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    alert_repo.update.assert_awaited_once()
    assert alert.ti_triggered is True


@pytest.mark.asyncio
async def test_ti_worker_lookup_exception_no_crash() -> None:
    """TIWorker handles TI lookup exceptions gracefully — still publishes."""
    bus = InMemoryEventBus()
    alert_id = uuid4()

    ti_client = MagicMock()
    ti_client.lookup = AsyncMock(side_effect=RuntimeError("TI provider down"))

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock()
    alert_repo.update = AsyncMock()

    stop = asyncio.Event()
    worker = TIWorker(bus=bus, ti_client=ti_client, alert_repo=alert_repo, stop_event=stop)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    collector_task = asyncio.create_task(
        _collect_published(bus, "alerts:enriched", count=1, timeout=2.0)
    )
    await asyncio.sleep(0.02)

    payload = json.dumps(
        {"alert_id": str(alert_id), "indicators": {"ips": ["1.2.3.4"], "hashes": []}}
    ).encode()
    await bus.publish("alerts:enrichment", payload)

    messages = await collector_task
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    # Worker survived; enriched message still published (with 0 score)
    assert len(messages) == 1
    assert messages[0]["ti_score"] == pytest.approx(0.0)
    assert messages[0]["malicious"] is False


@pytest.mark.asyncio
async def test_ti_worker_missing_alert_id_no_crash() -> None:
    """TIWorker handles payload without alert_id without crashing."""
    bus = InMemoryEventBus()

    ti_client = MagicMock()
    ti_client.lookup = AsyncMock()

    alert_repo = MagicMock()

    stop = asyncio.Event()
    worker = TIWorker(bus=bus, ti_client=ti_client, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    payload = json.dumps({"indicators": {"ips": ["1.2.3.4"], "hashes": []}}).encode()
    await bus.publish("alerts:enrichment", payload)
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    ti_client.lookup.assert_not_called()


@pytest.mark.asyncio
async def test_ti_worker_counts_total_malicious() -> None:
    """TIWorker increments _total_malicious only for malicious lookups."""
    bus = InMemoryEventBus()
    malicious_report = _make_ti_report(malicious=True, max_score=90.0)
    benign_report = _make_ti_report(malicious=False, max_score=5.0)

    call_count = 0

    async def _side_effect(indicator: str, itype: str) -> AggregatedTIReport:
        nonlocal call_count
        call_count += 1
        # First call malicious, second benign
        return malicious_report if call_count == 1 else benign_report

    ti_client = MagicMock()
    ti_client.lookup = AsyncMock(side_effect=_side_effect)

    alert_1 = _make_alert()
    alert_2 = _make_alert()

    alert_repo = MagicMock()
    alert_repo.get = AsyncMock(side_effect=[alert_1, alert_2])
    alert_repo.update = AsyncMock()

    stop = asyncio.Event()
    worker = TIWorker(bus=bus, ti_client=ti_client, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    for _ in range(2):
        a = _make_alert()
        payload = json.dumps(
            {"alert_id": str(a.alert_id), "indicators": {"ips": ["1.2.3.4"], "hashes": []}}
        ).encode()
        await bus.publish("alerts:enrichment", payload)

    await asyncio.sleep(0.15)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    # First message was malicious, second was benign
    assert worker._total_malicious == 1
    assert worker._total_processed == 2


@pytest.mark.asyncio
async def test_ti_worker_invalid_json_no_crash() -> None:
    """TIWorker handles unparseable messages without crashing."""
    bus = InMemoryEventBus()

    ti_client = MagicMock()
    ti_client.lookup = AsyncMock()
    alert_repo = MagicMock()

    stop = asyncio.Event()
    worker = TIWorker(bus=bus, ti_client=ti_client, alert_repo=alert_repo, stop_event=stop)

    task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    await bus.publish("alerts:enrichment", b"{not valid json")
    await asyncio.sleep(0.05)

    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    ti_client.lookup.assert_not_called()
