"""BackpressureController — monitors Redis Streams lag and throttles agents.

When the events:raw stream accumulates more than LAG_THRESHOLD unread messages,
the controller sends a SET_THROTTLE command to every connected agent via the
commands:{cn} bus topic.  In dev/test (no Redis URL) the controller is a no-op.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Callable
from typing import Any

from oseye.core.observability import get_logger

_logger = get_logger(__name__)

# BP-KEY: we monitor the *raw* stream (events:raw) rather than events:normalized.
# Rationale: raw represents the producer-side queue; measuring it before
# normalisation lets us throttle agents early — before CPU-intensive normalisation
# adds further latency. If the normalised stream were monitored instead, we would
# only react after the expensive step had already occurred.
_EVENTS_RAW_KEY = "events:raw"
_CHECK_INTERVAL_S = 10
_LAG_THRESHOLD = 10_000
_LAG_CLEAR_THRESHOLD = 5_000


class BackpressureController:
    """Periodically measures Redis Streams lag and issues SET_THROTTLE commands.

    Args:
        bus: EventBus used to publish commands to agents.
        get_active_cns: Callable returning the current set of active agent CNs.
        redis_url: Redis connection string.  None disables lag measurement (dev mode).
        lag_threshold: Message count above which throttling is triggered.
    """

    def __init__(
        self,
        bus: Any,
        get_active_cns: Callable[[], frozenset[str]],
        redis_url: str | None = None,
        lag_threshold: int = _LAG_THRESHOLD,
    ) -> None:
        self._bus = bus
        self._get_active_cns = get_active_cns
        self._redis_url = redis_url
        self._lag_threshold = lag_threshold
        self._redis_client: Any = None
        self._current_factor: float = 1.0

    async def _get_client(self) -> Any | None:
        if self._redis_url is None:
            return None
        if self._redis_client is None:
            try:
                import redis.asyncio as aioredis
                self._redis_client = await aioredis.from_url(
                    self._redis_url,
                    decode_responses=False,
                    socket_connect_timeout=3,
                )
            except Exception as exc:  # noqa: BLE001
                _logger.warning("backpressure_redis_connect_failed", error=str(exc))
                return None
        return self._redis_client

    async def _measure_lag(self) -> int:
        client = await self._get_client()
        if client is None:
            return 0
        try:
            length = await client.xlen(_EVENTS_RAW_KEY)
            return int(length)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("backpressure_xlen_failed", error=str(exc))
            return 0

    async def _publish_throttle(self, factor: float) -> None:
        cns = self._get_active_cns()
        if not cns:
            return
        payload = json.dumps({
            "command_id": str(uuid.uuid4()),
            "command_type": "SET_THROTTLE",
            "payload": {"factor": round(factor, 2)},
        }).encode()
        for cn in cns:
            try:
                await self._bus.publish(f"commands:{cn}", payload)
            except Exception as exc:  # noqa: BLE001
                _logger.warning("backpressure_publish_failed", cn=cn, error=str(exc))
        _logger.info("backpressure_throttle_sent", factor=factor, agents=len(cns))

    async def _check_and_throttle(self) -> None:
        lag = await self._measure_lag()
        if lag > self._lag_threshold:
            # Linear scale: lag=10k→factor=0.9, lag=100k→factor=0.1 (floor 0.1)
            factor = max(0.1, 1.0 - (lag - self._lag_threshold) / 100_000)
            if abs(factor - self._current_factor) >= 0.05:
                self._current_factor = factor
                await self._publish_throttle(factor)
                _logger.info("backpressure_active", lag=lag, factor=factor)
        elif lag < _LAG_CLEAR_THRESHOLD and self._current_factor < 1.0:
            self._current_factor = 1.0
            await self._publish_throttle(1.0)
            _logger.info("backpressure_cleared", lag=lag)

    async def run(self) -> None:
        """Background loop — call as an asyncio task."""
        _logger.info(
            "backpressure_controller_started",
            redis=bool(self._redis_url),
            lag_threshold=self._lag_threshold,
        )
        while True:
            await asyncio.sleep(_CHECK_INTERVAL_S)
            try:
                await self._check_and_throttle()
            except Exception as exc:  # noqa: BLE001
                _logger.error("backpressure_check_error", error=str(exc))

    async def close(self) -> None:
        if self._redis_client is not None:
            try:
                await self._redis_client.aclose()
            except Exception:  # noqa: BLE001
                pass
