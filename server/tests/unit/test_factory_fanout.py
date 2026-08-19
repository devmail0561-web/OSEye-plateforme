"""Tests for create_worker_bus fan-out behavior."""

from __future__ import annotations

import asyncio
import os

import pytest

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-32chars-for-pytest-ok")

from oseye.bus.factory import create_bus, create_worker_bus  # noqa: E402
from oseye.bus.memory_bus import InMemoryEventBus  # noqa: E402
from oseye.bus.redis_bus import RedisEventBus  # noqa: E402
from oseye.config import Settings  # noqa: E402


@pytest.fixture
def settings_no_redis() -> Settings:
    return Settings.model_construct(redis_url=None)


def test_create_worker_bus_inmemory_returns_shared(settings_no_redis: Settings) -> None:
    """In-memory mode: create_worker_bus returns the same shared instance."""
    shared = create_bus(settings_no_redis)
    worker_bus = create_worker_bus(settings_no_redis, shared, "oseye-rules")
    assert worker_bus is shared


def test_create_worker_bus_redis_returns_new_instance() -> None:
    """Redis mode: create_worker_bus returns a distinct RedisEventBus instance."""
    settings = Settings.model_construct(redis_url="redis://localhost:6379/0")
    shared = InMemoryEventBus()
    worker_bus = create_worker_bus(settings, shared, "oseye-rules")
    assert worker_bus is not shared
    assert isinstance(worker_bus, RedisEventBus)


def test_create_worker_bus_redis_different_groups_distinct() -> None:
    """Redis mode: each group gets its own distinct bus instance."""
    settings = Settings.model_construct(redis_url="redis://localhost:6379/0")
    shared = InMemoryEventBus()
    bus1 = create_worker_bus(settings, shared, "oseye-rules")
    bus2 = create_worker_bus(settings, shared, "oseye-ml")
    assert bus1 is not bus2


@pytest.mark.asyncio
async def test_inmemory_fanout_two_workers_via_factory(settings_no_redis: Settings) -> None:
    """Two worker buses (InMemory) both receive the same published event."""
    shared = create_bus(settings_no_redis)
    w1 = create_worker_bus(settings_no_redis, shared, "oseye-rules")
    w2 = create_worker_bus(settings_no_redis, shared, "oseye-ml")

    sub1 = await w1.subscribe("events:normalized")
    sub2 = await w2.subscribe("events:normalized")

    await shared.publish("events:normalized", b"test-event")

    async def get_one(gen):  # type: ignore[no-untyped-def]
        async for m in gen:
            return m

    r1, r2 = await asyncio.gather(
        asyncio.wait_for(get_one(sub1), timeout=1.0),
        asyncio.wait_for(get_one(sub2), timeout=1.0),
    )
    assert r1 == b"test-event"
    assert r2 == b"test-event"

    await shared.close()


@pytest.mark.asyncio
async def test_inmemory_six_workers_all_receive(settings_no_redis: Settings) -> None:
    """All six worker groups receive the same event (simulates full server setup)."""
    groups = [
        "oseye-storage", "oseye-rules", "oseye-ml",
        "oseye-ti", "oseye-correlation", "oseye-decision",
    ]
    shared = create_bus(settings_no_redis)
    subs = [
        await create_worker_bus(settings_no_redis, shared, g).subscribe("events:normalized")
        for g in groups
    ]

    await shared.publish("events:normalized", b"fan-out-check")

    async def get_one(gen):  # type: ignore[no-untyped-def]
        async for m in gen:
            return m

    results = await asyncio.gather(
        *[asyncio.wait_for(get_one(sub), timeout=1.0) for sub in subs]
    )
    assert all(r == b"fan-out-check" for r in results)

    await shared.close()
