"""Unit tests for Phase 4 M25 — Threat Intelligence layer.

Covers: AggregatedTIReport aggregation, MemoryTICache, AbuseIPDBProvider,
VirusTotalProvider, ThreatIntelClient (providers + cache).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock
from uuid import uuid4

import httpx
import pytest

from oseye.threat_intel.cache import MemoryTICache
from oseye.threat_intel.client import ThreatIntelClient
from oseye.threat_intel.models import AggregatedTIReport, ThreatIntelReport
from oseye.threat_intel.providers.abuseipdb import AbuseIPDBProvider
from oseye.threat_intel.providers.virustotal import VirusTotalProvider

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_report(
    indicator: str = "1.2.3.4",
    score: float = 50.0,
    malicious: bool = False,
    provider: str = "test_provider",
    tags: list[str] | None = None,
) -> ThreatIntelReport:
    return ThreatIntelReport(
        indicator=indicator,
        indicator_type="ip",
        score=score,
        malicious=malicious,
        provider=provider,
        tags=tags or [],
        cached_at=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# 1. AggregatedTIReport aggregation via ThreatIntelClient._aggregate
# ---------------------------------------------------------------------------


def test_aggregated_ti_report_max_score_malicious_tags_union() -> None:
    """_aggregate: max_score = max, malicious = any(reports), tags = union."""
    now = datetime.now(tz=timezone.utc)
    r1 = _make_report(score=60.0, malicious=False, provider="p1", tags=["ssh", "brute-force"])
    r2 = _make_report(score=80.0, malicious=True, provider="p2", tags=["brute-force", "malware"])

    result = ThreatIntelClient._aggregate("1.2.3.4", "ip", [r1, r2])

    assert result.max_score == 80.0
    assert result.malicious is True
    assert set(result.tags) == {"ssh", "brute-force", "malware"}
    assert "p1" in result.providers
    assert "p2" in result.providers
    assert len(result.reports) == 2


# ---------------------------------------------------------------------------
# 2–4. MemoryTICache
# ---------------------------------------------------------------------------


async def test_memory_cache_miss() -> None:
    """get() on empty cache returns None."""
    cache = MemoryTICache()
    result = await cache.get("ip", "1.2.3.4")
    assert result is None


async def test_memory_cache_set_and_get_hit() -> None:
    """set() followed by get() returns the stored report."""
    cache = MemoryTICache()
    report = _make_report()
    await cache.set("ip", "1.2.3.4", report)
    result = await cache.get("ip", "1.2.3.4")
    assert result is not None
    assert result.indicator == "1.2.3.4"
    assert result.score == report.score


async def test_memory_cache_ttl_expired() -> None:
    """set() with negative TTL (already-expired) causes get() to return None."""
    cache = MemoryTICache()
    report = _make_report()
    # ttl=-1 → expires_at = monotonic() - 1, which is already past
    await cache.set("ip", "1.2.3.4", report, ttl=-1)
    result = await cache.get("ip", "1.2.3.4")
    assert result is None


# ---------------------------------------------------------------------------
# 5–6. AbuseIPDBProvider
# ---------------------------------------------------------------------------


async def test_abuseipdb_no_api_key_returns_none() -> None:
    """AbuseIPDBProvider with empty api_key returns None without HTTP call."""
    provider = AbuseIPDBProvider(api_key="")
    result = await provider.lookup_ip("1.2.3.4")
    assert result is None
    await provider.close()


async def test_abuseipdb_http_mock_response() -> None:
    """AbuseIPDBProvider builds correct ThreatIntelReport from mocked HTTP response."""
    IP = "198.51.100.10"
    mock_payload = {
        "data": {
            "ipAddress": IP,
            "abuseConfidenceScore": 90.0,
            "isWhitelisted": False,
            "reports": [
                {"categories": [18, 22]},  # 18=brute-force, 22=ssh
            ],
            "lastReportedAt": "2026-07-01T12:00:00+00:00",
        }
    }

    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=mock_payload)

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        provider = AbuseIPDBProvider(api_key="test-key-abc", http_client=http_client)
        report = await provider.lookup_ip(IP)

    assert report is not None
    assert report.indicator == IP
    assert report.indicator_type == "ip"
    assert report.score == 90.0
    assert report.malicious is True
    assert report.provider == "abuseipdb"
    assert "brute-force" in report.tags
    assert "ssh" in report.tags
    assert report.last_seen is not None


# ---------------------------------------------------------------------------
# 7. VirusTotalProvider
# ---------------------------------------------------------------------------


async def test_virustotal_no_api_key_returns_none() -> None:
    """VirusTotalProvider with api_key=None returns None without HTTP call."""
    provider = VirusTotalProvider(api_key=None)
    result = await provider.lookup_ip("1.2.3.4")
    assert result is None
    await provider.close()


# ---------------------------------------------------------------------------
# 8–10. ThreatIntelClient
# ---------------------------------------------------------------------------


async def test_ti_client_all_providers_return_none() -> None:
    """When all providers return None, aggregated report has max_score=0 and malicious=False."""
    mock_provider = AsyncMock()
    mock_provider.name = "mock_provider"
    mock_provider.lookup_ip.return_value = None
    mock_provider.close = AsyncMock()

    cache = MemoryTICache()
    client = ThreatIntelClient(providers=[mock_provider], cache=cache)
    result = await client.lookup("1.2.3.4", "ip")
    await client.close()

    assert isinstance(result, AggregatedTIReport)
    assert result.max_score == 0.0
    assert result.malicious is False
    assert result.providers == []
    assert result.tags == []


async def test_ti_client_one_provider_report_aggregated_correctly() -> None:
    """When one provider returns a report, aggregated report reflects it."""
    now = datetime.now(tz=timezone.utc)
    mock_report = _make_report(
        score=75.0, malicious=True, provider="abuseipdb", tags=["ssh"]
    )

    mock_provider = AsyncMock()
    mock_provider.name = "abuseipdb"
    mock_provider.lookup_ip.return_value = mock_report
    mock_provider.close = AsyncMock()

    cache = MemoryTICache()
    client = ThreatIntelClient(providers=[mock_provider], cache=cache)
    result = await client.lookup("1.2.3.4", "ip")
    await client.close()

    assert result.max_score == 75.0
    assert result.malicious is True
    assert "abuseipdb" in result.providers
    assert "ssh" in result.tags


async def test_ti_client_cache_hit_skips_provider_calls() -> None:
    """When the cache already holds an aggregated stub, providers are never called."""
    now = datetime.now(tz=timezone.utc)
    cache = MemoryTICache()

    # Pre-populate the cache with an aggregated stub (same format the client writes)
    stub = ThreatIntelReport(
        indicator="1.2.3.4",
        indicator_type="ip",
        score=55.0,
        malicious=True,
        provider="_aggregated",
        tags=["port-scan"],
        raw={
            "max_score": 55.0,
            "malicious": True,
            "providers": ["abuseipdb"],
            "tags": ["port-scan"],
        },
        cached_at=now,
    )
    await cache.set("ip", "1.2.3.4", stub)

    mock_provider = AsyncMock()
    mock_provider.name = "abuseipdb"
    mock_provider.close = AsyncMock()

    client = ThreatIntelClient(providers=[mock_provider], cache=cache)
    result = await client.lookup("1.2.3.4", "ip")
    await client.close()

    # Provider must NOT have been queried
    mock_provider.lookup_ip.assert_not_called()
    assert result.max_score == 55.0
    assert result.malicious is True
    assert "port-scan" in result.tags


# ---------------------------------------------------------------------------
# 11. ti_unavailable flag
# ---------------------------------------------------------------------------


async def test_ti_client_all_providers_fail_sets_ti_unavailable() -> None:
    """When all providers raise exceptions, ti_unavailable=True in the report."""
    mock_provider = AsyncMock()
    mock_provider.name = "mock_provider"
    mock_provider.lookup_ip.side_effect = Exception("network error")
    mock_provider.close = AsyncMock()

    cache = MemoryTICache()
    client = ThreatIntelClient(providers=[mock_provider], cache=cache)
    result = await client.lookup("1.2.3.4", "ip")
    await client.close()

    assert result.ti_unavailable is True
    assert result.max_score == 0.0


async def test_ti_client_no_providers_not_unavailable() -> None:
    """With zero providers configured, ti_unavailable stays False (nothing to fail)."""
    cache = MemoryTICache()
    client = ThreatIntelClient(providers=[], cache=cache)
    result = await client.lookup("1.2.3.4", "ip")
    await client.close()

    assert result.ti_unavailable is False


# ---------------------------------------------------------------------------
# 12. Circuit breaker on AbuseIPDB
# ---------------------------------------------------------------------------


async def test_abuseipdb_circuit_open_returns_none() -> None:
    """When the circuit breaker is already open, lookup_ip returns None without HTTP."""
    from oseye.threat_intel.breaker import AsyncCircuitBreaker

    # Force breaker into open state by exhausting fail_max
    breaker = AsyncCircuitBreaker(fail_max=1, reset_timeout=9999, name="test")
    try:
        async def _fail() -> None:
            raise Exception("forced open")
        await breaker.call(_fail)
    except Exception:
        pass

    assert breaker.state == "open"

    async def _handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("HTTP should not be called when circuit is open")

    transport = httpx.MockTransport(_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        provider = AbuseIPDBProvider(api_key="test-key", http_client=http_client, breaker=breaker)
        result = await provider.lookup_ip("1.2.3.4")

    assert result is None


# ---------------------------------------------------------------------------
# 13. Retry on transient errors
# ---------------------------------------------------------------------------


async def test_retry_async_retries_on_connect_error() -> None:
    """retry_async retries up to N times on ConnectError before returning None."""
    from oseye.threat_intel.retry import retry_async

    call_count = 0

    async def flaky() -> None:
        nonlocal call_count
        call_count += 1
        raise httpx.ConnectError("refused")

    result = await retry_async(flaky, attempts=3, base_delay=0.0, label="test")
    assert result is None
    assert call_count == 3


async def test_retry_async_succeeds_on_second_attempt() -> None:
    """retry_async returns the result as soon as one attempt succeeds."""
    from oseye.threat_intel.retry import retry_async

    call_count = 0

    async def flaky() -> str:
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise httpx.ConnectError("refused")
        return "ok"

    result = await retry_async(flaky, attempts=3, base_delay=0.0, label="test")
    assert result == "ok"
    assert call_count == 2


async def test_retry_async_no_retry_on_4xx() -> None:
    """retry_async does not retry on HTTP 4xx (client error)."""
    from oseye.threat_intel.retry import retry_async

    call_count = 0

    async def client_error() -> None:
        nonlocal call_count
        call_count += 1
        raise httpx.HTTPStatusError(
            "not found",
            request=httpx.Request("GET", "http://x"),
            response=httpx.Response(404),
        )

    result = await retry_async(client_error, attempts=3, base_delay=0.0, label="test")
    assert result is None
    assert call_count == 1  # no retry on 4xx
