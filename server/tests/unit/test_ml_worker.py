"""Unit tests for MLWorker (P6.06)."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path

import pytest

from oseye.bus.memory_bus import InMemoryEventBus
from oseye.core.schema import UniversalEvent
from oseye.ml_engine.engine import MLEngine
from oseye.workers.ml_worker import MLWorker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event_json(hostname: str = "host-a", category: str = "process") -> bytes:
    event = UniversalEvent(
        event_id=uuid.uuid4(),
        timestamp_ns=time.time_ns(),
        hostname=hostname,
        agent_id=uuid.uuid4(),
        category=category,
        type="exec",
        severity="info",
        collector="procfs",
        hash_chain="a" * 64,
    )
    return event.model_dump_json().encode()


async def _collect_published(bus: InMemoryEventBus, topic: str, count: int, timeout: float = 2.0) -> list[dict]:
    """Subscribe and collect up to *count* messages from *topic*."""
    results: list[dict] = []
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ml_worker_publishes_score():
    """MLWorker publishes a score to analysis:ml for every valid event."""
    bus = InMemoryEventBus()
    engine = MLEngine()
    stop = asyncio.Event()
    worker = MLWorker(
        bus=bus,
        engine=engine,
        checkpoint_path=Path("/tmp/oseye_test_checkpoint.pkl"),
        checkpoint_interval_s=9999,
        stop_event=stop,
    )

    # Start collector before worker so the subscription is registered first.
    collector_task = asyncio.create_task(_collect_published(bus, "analysis:ml", count=3))
    await asyncio.sleep(0.02)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    for _ in range(3):
        await bus.publish("events:normalized", make_event_json())

    await asyncio.sleep(0.1)
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    results = await collector_task
    assert len(results) == 3
    for r in results:
        assert "event_id" in r
        assert "hostname" in r
        assert "category" in r
        assert "ml_score" in r
        assert 0.0 <= r["ml_score"] <= 100.0


@pytest.mark.asyncio
async def test_ml_worker_score_is_zero_cold_start():
    """Cold-start: score must be 0 for the first min_samples events."""
    bus = InMemoryEventBus()
    engine = MLEngine()
    stop = asyncio.Event()
    worker = MLWorker(
        bus=bus,
        engine=engine,
        checkpoint_path=Path("/tmp/oseye_test_checkpoint2.pkl"),
        stop_event=stop,
    )

    collector_task = asyncio.create_task(_collect_published(bus, "analysis:ml", count=3))
    await asyncio.sleep(0.02)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    for _ in range(3):
        await bus.publish("events:normalized", make_event_json())

    await asyncio.sleep(0.1)
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    results = await collector_task
    # During cold-start all scores must be 0
    for r in results:
        assert r["ml_score"] == 0.0


@pytest.mark.asyncio
async def test_ml_worker_skips_invalid_json():
    """MLWorker ignores unparseable messages without crashing."""
    bus = InMemoryEventBus()
    engine = MLEngine()
    stop = asyncio.Event()
    worker = MLWorker(
        bus=bus,
        engine=engine,
        checkpoint_path=Path("/tmp/oseye_test_checkpoint3.pkl"),
        stop_event=stop,
    )

    collector_task = asyncio.create_task(_collect_published(bus, "analysis:ml", count=1))
    await asyncio.sleep(0.02)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    await bus.publish("events:normalized", b"NOT_VALID_JSON")
    await bus.publish("events:normalized", make_event_json())

    await asyncio.sleep(0.1)
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    results = await collector_task
    # Only the valid event should have produced a score.
    assert len(results) == 1


@pytest.mark.asyncio
async def test_ml_worker_publish_error_does_not_crash():
    """MLWorker continues even if bus.publish raises."""

    class BrokenBus(InMemoryEventBus):
        async def publish(self, topic: str, message: bytes) -> None:
            if topic == "analysis:ml":
                raise RuntimeError("publish failed")
            await super().publish(topic, message)

    bus = BrokenBus()
    engine = MLEngine()
    stop = asyncio.Event()
    worker = MLWorker(
        bus=bus,
        engine=engine,
        checkpoint_path=Path("/tmp/oseye_test_checkpoint4.pkl"),
        stop_event=stop,
    )

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    for _ in range(2):
        await bus.publish("events:normalized", make_event_json())

    await asyncio.sleep(0.1)
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task
    # No uncaught exception — test passes if we reach here.


@pytest.mark.asyncio
async def test_ml_worker_checkpoint_on_stop(tmp_path: Path):
    """MLWorker saves a checkpoint file when it stops."""
    bus = InMemoryEventBus()
    engine = MLEngine()
    checkpoint = tmp_path / "model.pkl"
    stop = asyncio.Event()
    worker = MLWorker(
        bus=bus,
        engine=engine,
        checkpoint_path=checkpoint,
        stop_event=stop,
    )

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    for _ in range(3):
        await bus.publish("events:normalized", make_event_json())

    await asyncio.sleep(0.1)
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    assert checkpoint.exists()


@pytest.mark.asyncio
async def test_ml_worker_loads_checkpoint_on_start(tmp_path: Path):
    """MLWorker loads an existing checkpoint on startup."""
    bus = InMemoryEventBus()
    engine = MLEngine()
    checkpoint = tmp_path / "model.pkl"

    # Pre-train the engine and save manually.
    for _ in range(5):
        event = UniversalEvent(
            event_id=uuid.uuid4(),
            timestamp_ns=time.time_ns(),
            hostname="host-ckpt",
            agent_id=uuid.uuid4(),
            category="network",
            type="connect",
            severity="info",
            collector="netlink",
            hash_chain="b" * 64,
        )
        engine.score_event(event)
    engine.save_checkpoint(checkpoint)
    pre_train_count = engine.model_count

    # Start a fresh engine + worker — it should load the checkpoint.
    engine2 = MLEngine()
    stop = asyncio.Event()
    worker = MLWorker(bus=bus, engine=engine2, checkpoint_path=checkpoint, stop_event=stop)

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.05)
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    assert engine2.model_count == pre_train_count


@pytest.mark.asyncio
async def test_ml_worker_scored_counter():
    """MLWorker.total_scored increments correctly."""
    bus = InMemoryEventBus()
    engine = MLEngine()
    stop = asyncio.Event()
    worker = MLWorker(
        bus=bus,
        engine=engine,
        checkpoint_path=Path("/tmp/oseye_test_ckpt_ctr.pkl"),
        stop_event=stop,
    )

    worker_task = asyncio.create_task(worker.run())
    await asyncio.sleep(0.02)

    for _ in range(5):
        await bus.publish("events:normalized", make_event_json())

    await asyncio.sleep(0.1)
    stop.set()
    worker_task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await worker_task

    assert worker._total_scored == 5
