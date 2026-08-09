from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from oseye.threat_intel.breaker import AsyncCircuitBreaker, CircuitOpenError
from oseye.threat_intel.models import ThreatIntelReport
from oseye.threat_intel.retry import retry_async

logger = logging.getLogger(__name__)

_VT_BASE_URL = "https://www.virustotal.com/api/v3"
_MALICIOUS_THRESHOLD = 10.0  # percent of engines flagging as malicious


class VirusTotalProvider:
    name = "virustotal"

    def __init__(
        self,
        api_key: str | None,
        http_client: httpx.AsyncClient | None = None,
        breaker: AsyncCircuitBreaker | None = None,
        fail_max: int = 5,
        reset_timeout: float = 60.0,
    ) -> None:
        self._api_key = api_key or ""
        self._breaker = breaker or AsyncCircuitBreaker(
            fail_max=fail_max,
            reset_timeout=reset_timeout,
            name="virustotal",
        )

        if http_client is None:
            self._http_client = httpx.AsyncClient(timeout=15.0)
            self._owns_client = True
        else:
            self._http_client = http_client
            self._owns_client = False

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    def _compute_score(self, stats: dict[str, int]) -> float:
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())
        if total == 0:
            return 0.0
        return (malicious / total) * 100.0

    def _parse_report(
        self,
        indicator: str,
        indicator_type: str,
        data: dict[str, Any],
    ) -> ThreatIntelReport:
        attributes: dict[str, Any] = data.get("attributes", {})
        stats: dict[str, int] = attributes.get("last_analysis_stats", {})
        score = self._compute_score(stats)

        # Tags from popular threat labels or categories
        tags: list[str] = []
        for result in attributes.get("last_analysis_results", {}).values():
            label: str = result.get("result") or ""
            if label and label not in tags:
                tags.append(label)
                if len(tags) >= 10:
                    break

        last_analysis_date: int | None = attributes.get("last_analysis_date")
        last_seen: datetime | None = None
        if last_analysis_date:
            last_seen = datetime.fromtimestamp(last_analysis_date, tz=UTC)

        return ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,  # type: ignore[arg-type]
            score=min(score, 100.0),
            malicious=score >= _MALICIOUS_THRESHOLD,
            provider=self.name,
            tags=tags,
            last_seen=last_seen,
            raw=dict(data),
            cached_at=datetime.now(tz=UTC),
        )

    async def _do_lookup(
        self, url: str, indicator: str, indicator_type: str
    ) -> ThreatIntelReport | None:
        response = await self._http_client.get(url, headers=self._headers())
        response.raise_for_status()
        data: dict[str, Any] = response.json().get("data", {})
        return self._parse_report(indicator, indicator_type, data)

    def supports(self, indicator_type: str) -> bool:
        """VirusTotal supports both IP and hash lookups (TI-005)."""
        return indicator_type in ("ip", "hash")

    async def _lookup_with_retry(
        self, url: str, indicator: str, indicator_type: str
    ) -> ThreatIntelReport | None:
        """Execute the HTTP lookup with exponential-backoff retry.

        TI-003: the entire retry loop is wrapped in a *single* breaker.call() so
        that only one logical failure (not one per attempt) is counted against the
        circuit breaker.
        TI-004: retry_async already short-circuits on 4xx errors without retrying.
        """
        try:
            return await self._breaker.call(
                lambda: retry_async(
                    lambda: self._do_lookup(url, indicator, indicator_type),
                    attempts=3,
                    base_delay=0.5,
                    label=f"virustotal/{indicator_type}/{indicator}",
                )
            )
        except CircuitOpenError:
            logger.warning(
                "VirusTotal circuit open — skipping lookup for %s", indicator
            )
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("VirusTotal lookup failed for %s: %s", indicator, exc)
            return None

    async def lookup_ip(self, ip: str) -> ThreatIntelReport | None:
        if not self._api_key:
            return None
        # TI-001: URL-encode the indicator to prevent path traversal
        url = f"{_VT_BASE_URL}/ip_addresses/{quote(ip, safe='')}"
        return await self._lookup_with_retry(url, ip, "ip")

    async def lookup_hash(self, hash_value: str) -> ThreatIntelReport | None:
        if not self._api_key:
            return None
        # TI-001: URL-encode the indicator to prevent path traversal
        url = f"{_VT_BASE_URL}/files/{quote(hash_value, safe='')}"
        return await self._lookup_with_retry(url, hash_value, "hash")

    async def close(self) -> None:
        if self._owns_client:
            await self._http_client.aclose()
