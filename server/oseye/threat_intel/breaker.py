"""Lightweight asyncio-native circuit breaker for TI provider calls.

pybreaker.call_async relies on Tornado's gen.coroutine and is incompatible
with plain asyncio.  This module provides a minimal equivalent.
"""

from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger(__name__)

_CLOSED = "closed"
_OPEN = "open"
_HALF_OPEN = "half_open"


class AsyncCircuitBreaker:
    """Async-native circuit breaker.

    States:
    - CLOSED  : normal operation, failures are counted
    - OPEN    : calls are rejected immediately; opens after fail_max failures
    - HALF_OPEN: one probe call allowed; success → CLOSED, failure → OPEN
    """

    def __init__(
        self,
        fail_max: int = 5,
        reset_timeout: float = 60.0,
        name: str = "circuit",
    ) -> None:
        self._fail_max = fail_max
        self._reset_timeout = reset_timeout
        self._name = name
        self._state = _CLOSED
        self._failure_count = 0
        self._opened_at: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state

    async def call(self, coro_fn: object) -> object:
        """Execute *coro_fn()* respecting circuit state.

        Raises CircuitOpenError if the circuit is open.
        """
        async with self._lock:
            if self._state == _OPEN:
                elapsed = time.monotonic() - self._opened_at
                if elapsed >= self._reset_timeout:
                    self._state = _HALF_OPEN
                    logger.info("circuit_half_open name=%s", self._name)
                else:
                    raise CircuitOpenError(
                        f"Circuit '{self._name}' is open "
                        f"({self._reset_timeout - elapsed:.0f}s remaining)"
                    )

        try:
            result = await coro_fn()  # type: ignore[operator]
        except Exception:
            async with self._lock:
                self._failure_count += 1
                if self._state == _HALF_OPEN or self._failure_count >= self._fail_max:
                    self._state = _OPEN
                    self._opened_at = time.monotonic()
                    logger.warning(
                        "circuit_opened name=%s failures=%d",
                        self._name,
                        self._failure_count,
                    )
            raise
        else:
            async with self._lock:
                if self._state == _HALF_OPEN:
                    logger.info("circuit_closed name=%s (recovered)", self._name)
                self._state = _CLOSED
                self._failure_count = 0
            return result


class CircuitOpenError(Exception):
    """Raised when a call is attempted on an open circuit."""
