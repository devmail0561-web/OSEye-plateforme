from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, cast

from oseye.threat_intel.cache import MemoryTICache, TICache
from oseye.threat_intel.models import AggregatedTIReport, ThreatIntelReport
from oseye.threat_intel.providers.base import ThreatIntelProvider

if TYPE_CHECKING:
    from oseye.core.schema import Alert

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 3600  # seconds
_DEFAULT_TIMEOUT = 5.0  # seconds


class ThreatIntelClient:
    """Aggregates multiple TI providers with a shared cache layer.

    Usage::

        async with ThreatIntelClient(providers=[...]) as client:
            report = await client.lookup("1.2.3.4", "ip")
    """

    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
        cache: TICache | None = None,
        cache_ttl: int = _DEFAULT_TTL,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._providers: list[ThreatIntelProvider] = providers or []
        self._cache: TICache = cache if cache is not None else MemoryTICache(default_ttl=cache_ttl)
        self._cache_ttl = cache_ttl
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Context-manager support
    # ------------------------------------------------------------------

    async def __aenter__(self) -> ThreatIntelClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def lookup(
        self,
        indicator: str,
        indicator_type: Literal["ip", "hash"],
    ) -> AggregatedTIReport:
        """Look up *indicator* across all providers, returning an aggregated report.

        Results are cached per indicator.  All provider calls run concurrently
        and are bounded by *self._timeout* seconds total.
        """
        # Cache hit — return early (cache stores the aggregated report keyed by indicator)
        cached = await self._cache.get(indicator_type, indicator)
        if cached is not None:
            # cached is a ThreatIntelReport; we wrap it as a minimal aggregated report
            # when it was written as an aggregated stub.  Check for the special provider name.
            if cached.provider == "_aggregated":
                # Reconstruct AggregatedTIReport from the raw field stored during set()
                raw = cached.raw
                return AggregatedTIReport(
                    indicator=cached.indicator,
                    indicator_type=cached.indicator_type,
                    max_score=float(cast(Any, raw.get("max_score", cached.score))),
                    malicious=bool(cast(Any, raw.get("malicious", cached.malicious))),
                    providers=cast(list[str], raw.get("providers", [])),
                    tags=cast(list[str], raw.get("tags", cached.tags)),
                    ti_unavailable=bool(cast(Any, raw.get("ti_unavailable", False))),
                    reports=[],
                    queried_at=cached.cached_at,
                )

        # Parallel provider lookups bounded by timeout
        async def _call_provider(provider: ThreatIntelProvider) -> ThreatIntelReport | None:
            try:
                if indicator_type == "ip":
                    return await provider.lookup_ip(indicator)
                return await provider.lookup_hash(indicator)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "ti_provider_error provider=%s indicator=%s error=%s",
                    provider.name,
                    indicator,
                    exc,
                )
                return None

        try:
            raw_results: list[ThreatIntelReport | None | BaseException] = (
                await asyncio.wait_for(
                    asyncio.gather(
                        *[_call_provider(p) for p in self._providers],
                        return_exceptions=True,
                    ),
                    timeout=self._timeout,
                )
            )
        except TimeoutError:
            logger.warning(
                "ti_lookup_timeout indicator=%s timeout=%.1f", indicator, self._timeout
            )
            raw_results = []

        reports: list[ThreatIntelReport] = []
        for item in raw_results:
            if isinstance(item, BaseException):
                logger.warning("ti_provider_exception indicator=%s error=%s", indicator, item)
            elif item is not None:
                reports.append(item)

        # TI-002: a global timeout with providers configured means TI is unavailable
        ti_unavailable = (len(raw_results) > 0 and not reports) or (
            not raw_results and len(self._providers) > 0 and not reports
        )
        aggregated = self._aggregate(
            indicator, indicator_type, reports, ti_unavailable=ti_unavailable
        )

        # Persist a lightweight stub into the cache so subsequent requests skip providers
        stub = ThreatIntelReport(
            indicator=indicator,
            indicator_type=indicator_type,
            score=aggregated.max_score,
            malicious=aggregated.malicious,
            provider="_aggregated",
            tags=aggregated.tags,
            raw={
                "max_score": aggregated.max_score,
                "malicious": aggregated.malicious,
                "providers": aggregated.providers,
                "tags": aggregated.tags,
                "ti_unavailable": aggregated.ti_unavailable,
            },
            cached_at=aggregated.queried_at,
        )
        await self._cache.set(indicator_type, indicator, stub, ttl=self._cache_ttl)

        return aggregated

    async def lookup_ip(self, ip: str) -> AggregatedTIReport:
        return await self.lookup(ip, "ip")

    async def lookup_hash(self, hash_value: str) -> AggregatedTIReport:
        return await self.lookup(hash_value, "hash")

    async def lookup_alert_indicators(self, alert: Alert) -> AggregatedTIReport | None:
        """Extract the best available indicator from *alert* and look it up.

        Priority: dst_ip > src_ip.  Returns *None* if no usable indicator is found.
        The Alert model does not carry file hashes directly; those live on
        UniversalEvent.  Only network indicators are therefore checked here.
        """
        indicator: str | None = None
        indicator_type: Literal["ip", "hash"] = "ip"

        # Try network indicators
        dst_ip = getattr(alert, "dst_ip", None)
        src_ip = getattr(alert, "src_ip", None)
        if dst_ip:
            indicator = dst_ip
            indicator_type = "ip"
        elif src_ip:
            indicator = src_ip
            indicator_type = "ip"

        if indicator is None:
            return None

        return await self.lookup(indicator, indicator_type)

    async def close(self) -> None:
        for provider in self._providers:
            try:
                await provider.close()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Error closing provider %s: %s", provider.name, exc)
        await self._cache.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate(
        indicator: str,
        indicator_type: str,
        reports: list[ThreatIntelReport],
        ti_unavailable: bool = False,
    ) -> AggregatedTIReport:
        max_score = 0.0
        malicious = False
        providers: list[str] = []
        all_tags: list[str] = []

        for report in reports:
            if report.score > max_score:
                max_score = report.score
            if report.malicious:
                malicious = True
            providers.append(report.provider)
            for tag in report.tags:
                if tag not in all_tags:
                    all_tags.append(tag)

        return AggregatedTIReport(
            indicator=indicator,
            indicator_type=indicator_type,  # type: ignore[arg-type]
            max_score=max_score,
            malicious=malicious,
            providers=providers,
            tags=all_tags,
            reports=reports,
            queried_at=datetime.now(tz=UTC),
            ti_unavailable=ti_unavailable,
        )
