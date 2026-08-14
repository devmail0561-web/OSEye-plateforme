from __future__ import annotations

import asyncio
import json
import time
from collections import OrderedDict
from typing import Any, Protocol, runtime_checkable

from oseye.threat_intel.models import ThreatIntelReport

_DEFAULT_TTL = 3600  # seconds


@runtime_checkable
class TICache(Protocol):
    async def get(self, indicator_type: str, indicator: str) -> ThreatIntelReport | None: ...

    async def set(
        self,
        indicator_type: str,
        indicator: str,
        report: ThreatIntelReport,
        ttl: int = _DEFAULT_TTL,
    ) -> None: ...

    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# In-memory cache with TTL
# ---------------------------------------------------------------------------

class MemoryTICache:
    """Thread-safe in-memory TI cache with lazy TTL eviction."""

    _MAX_SIZE = 10_000  # TI-03: cap to prevent unbounded growth

    def __init__(self, default_ttl: int = _DEFAULT_TTL) -> None:
        self._default_ttl = default_ttl
        # TI-03: OrderedDict preserves insertion order for LRU eviction
        # key -> (expires_at: float, report: ThreatIntelReport)
        self._store: OrderedDict[str, tuple[float, ThreatIntelReport]] = OrderedDict()
        self._lock = asyncio.Lock()

    @staticmethod
    def _key(indicator_type: str, indicator: str) -> str:
        return f"{indicator_type}:{indicator}"

    async def get(self, indicator_type: str, indicator: str) -> ThreatIntelReport | None:
        key = self._key(indicator_type, indicator)
        async with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires_at, report = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return report

    async def set(
        self,
        indicator_type: str,
        indicator: str,
        report: ThreatIntelReport,
        ttl: int = _DEFAULT_TTL,
    ) -> None:
        key = self._key(indicator_type, indicator)
        expires_at = time.monotonic() + ttl
        async with self._lock:
            # TI-03: LRU eviction — remove existing key first (re-insert at end),
            # then evict the oldest entry if the store is at capacity.
            if key in self._store:
                del self._store[key]
            elif len(self._store) >= self._MAX_SIZE:
                self._store.popitem(last=False)  # remove oldest entry
            self._store[key] = (expires_at, report)

    async def close(self) -> None:
        async with self._lock:
            self._store.clear()


# ---------------------------------------------------------------------------
# Redis-backed cache with SETEX
# ---------------------------------------------------------------------------

class RedisTICache:
    """Redis-backed TI cache using SETEX with JSON serialisation."""

    _KEY_PREFIX = "ti:cache"

    def __init__(self, redis_client: Any, default_ttl: int = _DEFAULT_TTL) -> None:
        self._redis = redis_client
        self._default_ttl = default_ttl

    @classmethod
    def _key(cls, indicator_type: str, indicator: str) -> str:
        return f"{cls._KEY_PREFIX}:{indicator_type}:{indicator}"

    async def get(self, indicator_type: str, indicator: str) -> ThreatIntelReport | None:
        raw = await self._redis.get(self._key(indicator_type, indicator))
        if raw is None:
            return None
        try:
            data = json.loads(raw)
            return ThreatIntelReport.model_validate(data)
        except Exception:
            return None

    async def set(
        self,
        indicator_type: str,
        indicator: str,
        report: ThreatIntelReport,
        ttl: int = _DEFAULT_TTL,
    ) -> None:
        key = self._key(indicator_type, indicator)
        payload = report.model_dump_json()
        await self._redis.setex(key, ttl, payload)

    async def close(self) -> None:
        await self._redis.aclose()
