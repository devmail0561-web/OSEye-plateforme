from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlparse

from oseye.threat_intel.models import ThreatIntelReport

logger = logging.getLogger(__name__)


class MISPProvider:
    """Stub provider for MISP integration — not yet implemented."""

    name = "misp"

    def __init__(self, misp_url: str | None = None, api_key: str | None = None) -> None:
        self._misp_url = misp_url or ""
        self._api_key = api_key or ""

        if self._misp_url:
            # TI-04: validate the MISP URL to prevent SSRF via loopback/private addresses
            parsed = urlparse(self._misp_url)
            if parsed.scheme not in ("http", "https"):
                raise ValueError(
                    f"MISP URL must use http/https, got {parsed.scheme!r}"
                )
            if parsed.hostname:
                try:
                    addr = ipaddress.ip_address(parsed.hostname)
                except ValueError:
                    pass  # hostname is a domain name, not an IP — acceptable
                else:
                    if addr.is_loopback or addr.is_private:
                        raise ValueError(
                            f"MISP URL must not point to a loopback/private address: "
                            f"{parsed.hostname}"
                        )
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
