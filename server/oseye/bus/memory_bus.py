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
        # PC-17: queues accept None as a sentinel value so close() can unblock
        # sleeping subscribers immediately instead of waiting for the 1-s timeout.
        self._topic_queues: dict[str, dict[int, asyncio.Queue[bytes | None]]] = {}
        self._pattern_queues: dict[int, tuple[str, asyncio.Queue[tuple[str, bytes] | None]]] = {}
        self._closed = False

    async def publish(self, topic: str, message: bytes) -> None:
        if self._closed:
            return
        for queue in list(self._topic_queues.get(topic, {}).values()):
            await queue.put(message)
        for pat, pqueue in list(self._pattern_queues.values()):
            if fnmatch.fnmatch(topic, pat):
                await pqueue.put((topic, message))

    async def publish_batch(self, topic: str, messages: list[bytes]) -> None:
        for msg in messages:
            await self.publish(topic, msg)

    async def subscribe(self, topic: str) -> AsyncGenerator[bytes, None]:
        """Return an async generator that yields messages on topic.

        The subscription is registered at await-time, before any iteration.
        """
        queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._topic_queues.setdefault(topic, {})[id(queue)] = queue
        return self._read_bytes(topic, queue)

    async def subscribe_pattern(self, pattern: str) -> AsyncGenerator[tuple[str, bytes], None]:
        """Return an async generator yielding (topic, message) for matching topics."""
        queue: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue()
        self._pattern_queues[id(queue)] = (pattern, queue)
        return self._read_tuples(pattern, queue)

    async def _read_bytes(
        self, topic: str, queue: asyncio.Queue[bytes | None]
    ) -> AsyncGenerator[bytes, None]:
        try:
            while not self._closed:
                try:
                    value = await asyncio.wait_for(queue.get(), timeout=1.0)
                    if value is None:  # PC-17: sentinel from close() — stop immediately
                        break
                    yield value
                except TimeoutError:
                    continue
        finally:
            subscribers = self._topic_queues.get(topic, {})
            subscribers.pop(id(queue), None)

    async def _read_tuples(
        self, pattern: str, queue: asyncio.Queue[tuple[str, bytes] | None]
    ) -> AsyncGenerator[tuple[str, bytes], None]:
        try:
            while not self._closed:
                try:
                    value = await asyncio.wait_for(queue.get(), timeout=1.0)
                    if value is None:  # PC-17: sentinel from close() — stop immediately
                        break
                    yield value
                except TimeoutError:
                    continue
        finally:
            self._pattern_queues.pop(id(queue), None)

    async def close(self) -> None:
        self._closed = True
        # PC-17: push a None sentinel into every queue so subscribers sleeping in
        # wait_for(..., timeout=1.0) wake up immediately instead of after ~1 second.
        for queues in list(self._topic_queues.values()):
            for queue in list(queues.values()):
                try:
                    queue.put_nowait(None)
                except asyncio.QueueFull:
                    pass
        for _pat, queue in list(self._pattern_queues.values()):
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                pass
