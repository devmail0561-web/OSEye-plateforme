"""In-memory EventBus for testing and local dev without Redis."""

from __future__ import annotations

import asyncio
import fnmatch
from collections.abc import AsyncGenerator


class InMemoryEventBus:
    """Async in-memory EventBus backed by asyncio queues.

    Suitable for unit tests and local dev runs without Redis.
    subscribe() and subscribe_pattern() are awaitable so the queue
    is registered before any publish() call — no messages are lost.
    """

    def __init__(self) -> None:
        self._topic_queues: dict[str, dict[int, asyncio.Queue[bytes]]] = {}
        self._pattern_queues: dict[int, tuple[str, asyncio.Queue[tuple[str, bytes]]]] = {}
        self._closed = False

    async def publish(self, topic: str, message: bytes) -> None:
        if self._closed:
            return
        for queue in list(self._topic_queues.get(topic, {}).values()):
            await queue.put(message)
        for pat, pqueue in list(self._pattern_queues.values()):
            if fnmatch.fnmatch(topic, pat):
                await pqueue.put((topic, message))

    async def subscribe(self, topic: str) -> AsyncGenerator[bytes, None]:
        """Return an async generator that yields messages on topic.

        The subscription is registered at await-time, before any iteration.
        """
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._topic_queues.setdefault(topic, {})[id(queue)] = queue
        return self._read_bytes(topic, queue)

    async def subscribe_pattern(self, pattern: str) -> AsyncGenerator[tuple[str, bytes], None]:
        """Return an async generator yielding (topic, message) for matching topics."""
        queue: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()
        self._pattern_queues[id(queue)] = (pattern, queue)
        return self._read_tuples(pattern, queue)

    async def _read_bytes(
        self, topic: str, queue: asyncio.Queue[bytes]
    ) -> AsyncGenerator[bytes, None]:
        try:
            while not self._closed:
                try:
                    yield await asyncio.wait_for(queue.get(), timeout=1.0)
                except TimeoutError:
                    continue
        finally:
            subscribers = self._topic_queues.get(topic, {})
            subscribers.pop(id(queue), None)

    async def _read_tuples(
        self, pattern: str, queue: asyncio.Queue[tuple[str, bytes]]
    ) -> AsyncGenerator[tuple[str, bytes], None]:
        try:
            while not self._closed:
                try:
                    yield await asyncio.wait_for(queue.get(), timeout=1.0)
                except TimeoutError:
                    continue
        finally:
            self._pattern_queues.pop(id(queue), None)

    async def close(self) -> None:
        self._closed = True
