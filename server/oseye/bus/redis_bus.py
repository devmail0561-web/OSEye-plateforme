"""Redis Streams EventBus implementation."""

from __future__ import annotations

import asyncio
import fnmatch
from collections.abc import AsyncGenerator
from typing import Any

import redis.asyncio as aioredis


class RedisEventBus:
    """EventBus backed by Redis Streams.

    Each topic maps to a Redis Stream key. Subscribers use a consumer
    group so messages survive brief disconnects.
    """

    def __init__(self, redis_url: str, consumer_group: str = "oseye") -> None:
        self._redis_url = redis_url
        self._group = consumer_group
        self._client: Any = None
        self._consumer_id = f"consumer-{id(self)}"
        self._closed = False

    async def _get_client(self) -> Any:
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

    async def subscribe(self, topic: str) -> AsyncGenerator[bytes, None]:
        client = await self._get_client()
        await self._ensure_group(client, topic)
        return self._read_stream(client, topic)

    async def subscribe_pattern(self, pattern: str) -> AsyncGenerator[tuple[str, bytes], None]:
        client = await self._get_client()
        return self._read_pattern(client, pattern)

    async def _read_stream(self, client: Any, topic: str) -> AsyncGenerator[bytes, None]:
        while not self._closed:
            try:
                results: list[Any] = await client.xreadgroup(
                    self._group,
                    self._consumer_id,
                    {topic: ">"},
                    count=10,
                    block=100,
                )
                if not results:
                    continue
                for _stream, messages in results:
                    for msg_id, fields in messages:
                        payload: bytes = fields.get(b"data", b"")
                        yield payload
                        await client.xack(topic, self._group, msg_id)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.1)

    async def _read_pattern(
        self, client: Any, pattern: str
    ) -> AsyncGenerator[tuple[str, bytes], None]:
        seen_topics: set[str] = set()
        while not self._closed:
            try:
                matching = []
                async for raw_key in client.scan_iter(match="*", count=100):
                    key_str = raw_key.decode() if isinstance(raw_key, bytes) else str(raw_key)
                    if fnmatch.fnmatch(key_str, pattern):
                        matching.append(key_str)
                for topic in matching:
                    if topic not in seen_topics:
                        await self._ensure_group(client, topic)
                        seen_topics.add(topic)
                if seen_topics:
                    streams: dict[str, str] = {t: ">" for t in seen_topics}
                    results = await client.xreadgroup(
                        self._group,
                        self._consumer_id,
                        streams,
                        count=10,
                        block=100,
                    )
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
                                await client.xack(stream_name, self._group, msg_id)
                else:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(0.1)

    async def close(self) -> None:
        self._closed = True
        if self._client is not None:
            await self._client.aclose()
            self._client = None
