from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from oseye.threat_intel.models import ThreatIntelReport

logger = logging.getLogger(__name__)

# Map the most common AbuseIPDB category IDs to human-readable strings
_CATEGORY_MAP: dict[int, str] = {
    18: "brute-force",
    22: "ssh",
    14: "port-scan",
    20: "exploited",
    21: "web-attack",
}

_ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider:
    name = "abuseipdb"

    def __init__(
        self,
        api_key: str,
        http_client: httpx.AsyncClient | None = None,
        breaker: Any | None = None,
    ) -> None:
        self._api_key = api_key or ""
        self._breaker = breaker

        if http_client is None:
            self._http_client = httpx.AsyncClient(timeout=10.0)
            self._owns_client = True
        else:
            self._http_client = http_client
            self._owns_client = False

    async def lookup_ip(self, ip: str) -> ThreatIntelReport | None:
        if not self._api_key:
            return None

        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": "true",
        }
        headers = {"Key": self._api_key, "Accept": "application/json"}

        try:
            response = await self._http_client.get(
                _ABUSEIPDB_CHECK_URL, params=params, headers=headers
            )
            response.raise_for_status()
            data: dict[str, Any] = response.json().get("data", {})
        except httpx.HTTPError as exc:
            logger.warning("AbuseIPDB lookup_ip failed for %s: %s", ip, exc)
            return None

        confidence_score: float = float(data.get("abuseConfidenceScore", 0))
        is_whitelisted: bool = bool(data.get("isWhitelisted", False))

        # Collect category IDs from individual reports and map to strings
        raw_reports: list[dict[str, Any]] = data.get("reports", [])
        seen_categories: set[int] = set()
        for report in raw_reports:
            for cat_id in report.get("categories", []):
                seen_categories.add(int(cat_id))

        tags: list[str] = [
            _CATEGORY_MAP[cid]
            for cid in seen_categories
            if cid in _CATEGORY_MAP
        ]

        last_reported_at: str | None = data.get("lastReportedAt")
        last_seen: datetime | None = None
        if last_reported_at:
            try:
                last_seen = datetime.fromisoformat(
                    last_reported_at.replace("Z", "+00:00")
                )
            except ValueError:
                pass

        return ThreatIntelReport(
            indicator=ip,
            indicator_type="ip",
            score=confidence_score,
            malicious=(confidence_score > 0) and (not is_whitelisted),
            provider=self.name,
            tags=tags,
            last_seen=last_seen,
            raw=dict(data),
            cached_at=datetime.now(tz=UTC),
        )

    async def lookup_hash(self, hash_value: str) -> ThreatIntelReport | None:
        # AbuseIPDB does not support hash lookups
        return None

    async def close(self) -> None:
        if self._owns_client:
            await self._http_client.aclose()
