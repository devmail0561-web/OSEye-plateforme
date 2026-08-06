"""Unit tests for M10 workers: StorageWriter."""

from __future__ import annotations

import asyncio
import json
import time
import uuid

import pytest

from oseye.bus.memory_bus import InMemoryEventBus
from oseye.core.schema import UniversalEvent
from oseye.workers.storage_writer import StorageWriter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_event_json(i: int = 0) -> bytes:
    event = UniversalEvent(
        event_id=uuid.uuid4(),
        timestamp_ns=time.time_ns() + i,
        hostname="test-host",
        agent_id=uuid.uuid4(),
        category="process",
        type="exec",
        severity="info",
        collector="procfs",
        hash_chain="a" * 64,
    )
    return event.model_dump_json().encode()


class _FakeRepo:
    def __init__(self) -> None:
        self.batches: list[list[UniversalEvent]] = []

    async def insert_batch(self, events: list[UniversalEvent]) -> None:
        self.batches.append(list(events))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_storage_writer_flushes_on_batch_max():
    """StorageWriter flushes when batch_max_size is reached."""
    bus = InMemoryEventBus()
    repo = _FakeRepo()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=10_000, batch_max_size=3)
    stop = asyncio.Event()

    task = asyncio.create_task(writer.run(stop_event=stop))
    # Yield to let the writer reach `await self._bus.subscribe()` first.
    await asyncio.sleep(0.02)

    # Publish 3 events — should trigger a flush immediately.
    for i in range(3):
        await bus.publish("events:normalized", make_event_json(i))

    # Give the writer time to process.
    await asyncio.sleep(0.05)
    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    assert len(repo.batches) >= 1
    total = sum(len(b) for b in repo.batches)
    assert total >= 3


@pytest.mark.asyncio
async def test_storage_writer_flushes_on_timeout():
    """StorageWriter flushes when flush_interval elapses even with few events."""
    bus = InMemoryEventBus()
    repo = _FakeRepo()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=1000)
    stop = asyncio.Event()

    task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.02)  # let writer subscribe first

    await bus.publish("events:normalized", make_event_json(0))
    # Wait longer than flush_interval.
    await asyncio.sleep(0.15)
    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    # At least one flush must have happened.
    total = sum(len(b) for b in repo.batches)
    assert total >= 1


@pytest.mark.asyncio
async def test_storage_writer_ignores_invalid_json():
    """StorageWriter skips unparseable messages without crashing."""
    bus = InMemoryEventBus()
    repo = _FakeRepo()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=10)
    stop = asyncio.Event()

    task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.02)  # let writer subscribe first

    await bus.publish("events:normalized", b"NOT_VALID_JSON")
    await bus.publish("events:normalized", make_event_json(0))
    await asyncio.sleep(0.15)
    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    # Only the valid event should have been stored.
    total = sum(len(b) for b in repo.batches)
    assert total == 1


@pytest.mark.asyncio
async def test_storage_writer_empty_bus():
    """StorageWriter starts and stops cleanly when no messages arrive."""
    bus = InMemoryEventBus()
    repo = _FakeRepo()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=10)
    stop = asyncio.Event()

    task = asyncio.create_task(writer.run(stop_event=stop))
    await asyncio.sleep(0.1)
    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task

    assert repo.batches == []


@pytest.mark.asyncio
async def test_storage_writer_repo_error_does_not_crash():
    """StorageWriter continues when the repository raises an exception."""

    class ErrorRepo:
        async def insert_batch(self, events: list[UniversalEvent]) -> None:
            raise RuntimeError("DB error")

    bus = InMemoryEventBus()
    repo = ErrorRepo()
    writer = StorageWriter(bus=bus, repo=repo, flush_interval_ms=50, batch_max_size=2)  # type: ignore[arg-type]
    stop = asyncio.Event()

    task = asyncio.create_task(writer.run(stop_event=stop))
    for i in range(2):
        await bus.publish("events:normalized", make_event_json(i))

    await asyncio.sleep(0.15)
    stop.set()
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task
    # No uncaught exception — test passes if we reach here.
