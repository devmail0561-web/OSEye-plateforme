"""Unit tests for InMemoryEventBus."""

from __future__ import annotations

import asyncio

import pytest

from oseye.bus.interface import EventBus
from oseye.bus.memory_bus import InMemoryEventBus


@pytest.fixture
def bus() -> InMemoryEventBus:
    return InMemoryEventBus()


async def collect_n(gen, n: int, timeout: float = 1.0) -> list:
    """Collect n items from an async generator within timeout seconds."""
    results = []
    async with asyncio.timeout(timeout):
        async for item in gen:
            results.append(item)
            if len(results) >= n:
                break
    return results


async def test_memory_bus_publish_subscribe(bus: InMemoryEventBus) -> None:
    sub = await bus.subscribe("events:raw:abc")
    await bus.publish("events:raw:abc", b"hello")
    results = await collect_n(sub, 1)
    assert results == [b"hello"]


async def test_memory_bus_multiple_messages(bus: InMemoryEventBus) -> None:
    messages = [b"msg1", b"msg2", b"msg3"]
    sub = await bus.subscribe("events:normalized")
    for m in messages:
        await bus.publish("events:normalized", m)
    results = await collect_n(sub, 3)
    assert results == messages


async def test_memory_bus_subscribe_pattern(bus: InMemoryEventBus) -> None:
    sub = await bus.subscribe_pattern("events:raw:*")
    await bus.publish("events:raw:agent-001", b"payload1")
    await bus.publish("events:raw:agent-002", b"payload2")
    results = await collect_n(sub, 2)
    topics = [r[0] for r in results]
    payloads = [r[1] for r in results]
    assert "events:raw:agent-001" in topics
    assert "events:raw:agent-002" in topics
    assert b"payload1" in payloads
    assert b"payload2" in payloads


async def test_memory_bus_pattern_no_match(bus: InMemoryEventBus) -> None:
    sub = await bus.subscribe_pattern("analysis:*")
    await bus.publish("events:raw:agent-x", b"nomatch")
    await bus.publish("analysis:ml", b"match")
    results = await collect_n(sub, 1)
    assert results == [("analysis:ml", b"match")]


async def test_memory_bus_multiple_subscribers(bus: InMemoryEventBus) -> None:
    sub1 = await bus.subscribe("decisions:completed")
    sub2 = await bus.subscribe("decisions:completed")
    await bus.publish("decisions:completed", b"decision-data")
    r1 = await collect_n(sub1, 1)
    r2 = await collect_n(sub2, 1)
    assert r1 == [b"decision-data"]
    assert r2 == [b"decision-data"]


async def test_memory_bus_different_topics_isolated(bus: InMemoryEventBus) -> None:
    sub_a = await bus.subscribe("topic:a")
    await bus.publish("topic:b", b"for-b-only")
    await bus.publish("topic:a", b"for-a")
    results = await collect_n(sub_a, 1)
    assert results == [b"for-a"]


async def test_memory_bus_close_stops_subscribers(bus: InMemoryEventBus) -> None:
    collected: list[bytes] = []
    sub = await bus.subscribe("some:topic")

    async def consumer() -> None:
        async for msg in sub:
            collected.append(msg)

    task = asyncio.create_task(consumer())
    await asyncio.sleep(0)
    await bus.publish("some:topic", b"before-close")
    await asyncio.sleep(0.1)
    await bus.close()
    await asyncio.wait_for(task, timeout=1.0)
    assert b"before-close" in collected


async def test_memory_bus_satisfies_protocol(bus: InMemoryEventBus) -> None:
    assert isinstance(bus, EventBus)


async def test_memory_bus_empty_message(bus: InMemoryEventBus) -> None:
    sub = await bus.subscribe("test:empty")
    await bus.publish("test:empty", b"")
    results = await collect_n(sub, 1)
    assert results == [b""]
