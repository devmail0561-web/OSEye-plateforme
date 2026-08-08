"""Async retry helper with exponential backoff for TI provider calls."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

import httpx

logger = logging.getLogger(__name__)

# Errors that warrant a retry (transient network/server issues)
_RETRYABLE = (
    httpx.ConnectError,
    httpx.RemoteProtocolError,
    httpx.ReadTimeout,
    httpx.ConnectTimeout,
)


async def retry_async[T](
    fn: Callable[[], Awaitable[T]],
    *,
    attempts: int = 3,
    base_delay: float = 0.5,
    label: str = "",
) -> T | None:
    """Call *fn* up to *attempts* times with exponential backoff.

    Returns the first successful result, or None after all attempts are
    exhausted.  Only retries on transient httpx errors; HTTP 4xx errors
    (client mistakes) are not retried.
    """
    delay = base_delay
    for attempt in range(1, attempts + 1):
        try:
            return await fn()
        except httpx.HTTPStatusError as exc:
            # 4xx → client error, not transient — don't retry
            if exc.response.status_code < 500:
                logger.warning(
                    "ti_client_error label=%s status=%d",
                    label,
                    exc.response.status_code,
                )
                return None
            # 5xx → server error, may be transient
            if attempt == attempts:
                logger.warning(
                    "ti_server_error_final label=%s status=%d attempt=%d",
                    label,
                    exc.response.status_code,
                    attempt,
                )
                return None
            logger.debug(
                "ti_retry label=%s status=%d attempt=%d delay=%.1f",
                label,
                exc.response.status_code,
                attempt,
                delay,
            )
        except _RETRYABLE as exc:
            if attempt == attempts:
                logger.warning(
                    "ti_network_error_final label=%s error=%s attempt=%d",
                    label,
                    exc,
                    attempt,
                )
                return None
            logger.debug(
                "ti_retry label=%s error=%s attempt=%d delay=%.1f",
                label,
                exc,
                attempt,
                delay,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ti_unexpected_error label=%s error=%s", label, exc)
            return None

        await asyncio.sleep(delay)
        delay *= 2

    return None  # unreachable but satisfies type checker
