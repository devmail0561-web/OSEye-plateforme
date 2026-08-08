from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

import httpx

from oseye.threat_intel.models import ThreatIntelReport

logger = logging.getLogger(__name__)

_VT_BASE_URL = "https://www.virustotal.com/api/v3"
_MALICIOUS_THRESHOLD = 10.0  # percent of engines flagging as malicious


class VirusTotalProvider:
    name = "virustotal"

    def __init__(
        self,
        api_key: str | None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._api_key = api_key or ""

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

    async def lookup_ip(self, ip: str) -> ThreatIntelReport | None:
        if not self._api_key:
            return None

        url = f"{_VT_BASE_URL}/ip_addresses/{ip}"
        try:
            response = await self._http_client.get(url, headers=self._headers())
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
        except httpx.HTTPError as exc:
            logger.warning("VirusTotal lookup_ip failed for %s: %s", ip, exc)
            return None

        data: dict[str, Any] = payload.get("data", {})
        return self._parse_report(ip, "ip", data)

    async def lookup_hash(self, hash_value: str) -> ThreatIntelReport | None:
        if not self._api_key:
            return None

        url = f"{_VT_BASE_URL}/files/{hash_value}"
        try:
            response = await self._http_client.get(url, headers=self._headers())
            response.raise_for_status()
            payload: dict[str, Any] = response.json()
        except httpx.HTTPError as exc:
            logger.warning(
                "VirusTotal lookup_hash failed for %s: %s", hash_value, exc
            )
            return None

        data: dict[str, Any] = payload.get("data", {})
        return self._parse_report(hash_value, "hash", data)

    async def close(self) -> None:
        if self._owns_client:
            await self._http_client.aclose()
