"""Redis Streams EventBus implementation."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any

import redis.asyncio as aioredis

from oseye.core.observability import get_logger

_logger = get_logger(__name__)

_MAX_BACKOFF = 30.0  # seconds


class RedisEventBus:
    """EventBus backed by Redis Streams.

    Each topic maps to a Redis Stream key. Subscribers use a consumer
    group so messages survive brief disconnects.
    """

    def __init__(
        self,
        redis_url: str,
        consumer_group: str = "oseye",
        read_batch_size: int = 100,
    ) -> None:
        self._redis_url = redis_url
        self._group = consumer_group
        self._read_batch_size = read_batch_size
        self._client: Any = None
        self._consumer_id = f"consumer-{id(self)}"
        self._closed = False
        self._lock = asyncio.Lock()

    async def _get_client(self) -> Any:
        if self._client is None:
            async with self._lock:
                if self._client is None:
                    self._client = await aioredis.from_url(
                        self._redis_url,
                        decode_responses=False,
                        socket_connect_timeout=5,
                    )
        return self._client

    async def _ensure_group(self, client: Any, topic: str) -> None:
        try:
            await client.xgroup_create(topic, self._group, id="0", mkstream=True)
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def publish(self, topic: str, message: bytes) -> None:
        client = await self._get_client()
        await client.xadd(topic, {"data": message})

    async def publish_batch(self, topic: str, messages: list[bytes]) -> None:
        if not messages:
            return
        client = await self._get_client()
        async with client.pipeline(transaction=False) as pipe:
            for msg in messages:
                pipe.xadd(topic, {"data": msg})
            await pipe.execute()

    async def subscribe(self, topic: str) -> AsyncGenerator[bytes, None]:
        client = await self._get_client()
        await self._ensure_group(client, topic)
        return self._read_stream(client, topic)

    async def subscribe_pattern(self, pattern: str) -> AsyncGenerator[tuple[str, bytes], None]:
        client = await self._get_client()
        return self._read_pattern(client, pattern)

    async def _read_stream(self, client: Any, topic: str) -> AsyncGenerator[bytes, None]:
        _backoff = 0.1
        while not self._closed:
            try:
                results: list[Any] = await client.xreadgroup(
                    self._group,
                    self._consumer_id,
                    {topic: ">"},
                    count=self._read_batch_size,
                    block=100,
                )
                _backoff = 0.1  # reset on success
                if not results:
                    continue
                for _stream, messages in results:
                    for msg_id, fields in messages:
                        payload: bytes = fields.get(b"data", b"")
                        yield payload
                    msg_ids = [msg_id for msg_id, _ in messages]
                    await client.xack(topic, self._group, *msg_ids)
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "redis_read_stream_error",
                    topic=topic,
                    error=str(exc),
                    backoff=_backoff,
                )
                await asyncio.sleep(_backoff)
                _backoff = min(_backoff * 2, _MAX_BACKOFF)

    async def _read_pattern(
        self, client: Any, pattern: str
    ) -> AsyncGenerator[tuple[str, bytes], None]:
        seen_topics: set[str] = set()
        streams: dict[str, str] = {}
        matching: list[str] = []
        _scan_interval = 5.0
        _last_scan = 0.0
        while not self._closed:
            try:
                # Throttle SCAN to once every 5s — new topics arrive rarely
                # (agent enrollment), not on every message.
                _now = asyncio.get_running_loop().time()
                if _now - _last_scan >= _scan_interval:
                    _last_scan = _now
                    matching.clear()
                    async for raw_key in client.scan_iter(match=pattern, count=100):
                        key_str = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
                        matching.append(key_str)
                # [MEDIUM-2] only rebuild streams dict when seen_topics changes
                new_topics = False
                for topic in matching:
                    if topic not in seen_topics:
                        await self._ensure_group(client, topic)
                        seen_topics.add(topic)
                        new_topics = True
                if new_topics:
                    streams = {t: ">" for t in seen_topics}
                if seen_topics:
                    try:
                        results = await client.xreadgroup(
                            self._group,
                            self._consumer_id,
                            streams,
                            count=self._read_batch_size,
                            block=100,
                        )
                    except aioredis.ResponseError as e:
                        # [LOW-1] purge disappeared streams from seen_topics
                        err_str = str(e)
                        to_remove = {t for t in seen_topics if f"'{t}'" in err_str or f'"{t}"' in err_str or err_str.endswith(t)}
                        if to_remove:
                            seen_topics -= to_remove
                            streams = {t: ">" for t in seen_topics}
                        await asyncio.sleep(0.1)
                        continue
                    if results:
                        for raw_stream, messages in results:
                            stream_name = (
                                raw_stream.decode()
                                if isinstance(raw_stream, bytes)
                                else str(raw_stream)
                            )
                            for msg_id, fields in messages:
                                payload = fields.get(b"data", b"")
                                yield stream_name, payload
                            # [MEDIUM-1] batch ACK
                            msg_ids = [msg_id for msg_id, _ in messages]
                            await client.xack(stream_name, self._group, *msg_ids)
                else:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001
                _logger.warning("redis_read_pattern_error", pattern=pattern, error=str(exc))
                await asyncio.sleep(0.1)

    async def close(self) -> None:
        self._closed = True
        if self._client is not None:
            await self._client.aclose()
            self._client = None
