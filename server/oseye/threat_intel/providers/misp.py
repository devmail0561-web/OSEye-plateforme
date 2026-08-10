from __future__ import annotations

import logging

from oseye.threat_intel.models import ThreatIntelReport

logger = logging.getLogger(__name__)


class MISPProvider:
    """Stub provider for MISP integration — not yet implemented."""

    name = "misp"

    def __init__(self, misp_url: str | None = None, api_key: str | None = None) -> None:
        self._misp_url = misp_url or ""
        self._api_key = api_key or ""

        if self._misp_url:
            # TI-MED-002: log only that MISP is configured, never the URL itself
            # (which may contain an internal hostname or embedded credentials).
            logger.warning(
                "MISP URL is configured but the MISP provider is not yet "
                "implemented. Threat intelligence lookups via MISP will return None."
            )

    async def lookup_ip(self, ip: str) -> ThreatIntelReport | None:
        return None

    async def lookup_hash(self, hash_value: str) -> ThreatIntelReport | None:
        return None

    async def close(self) -> None:
        pass
