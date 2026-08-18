from __future__ import annotations

import ipaddress
import logging
import socket
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
                # Resolve the hostname and check every resolved address to prevent
                # SSRF via hostname pointing to a private/internal address (H-17).
                # TI-04: set a short timeout to avoid blocking the event loop during init.
                try:
                    socket.setdefaulttimeout(2.0)
                    resolved = socket.getaddrinfo(parsed.hostname, None)
                    socket.setdefaulttimeout(None)
                    for _, _, _, _, sockaddr in resolved:
                        addr = ipaddress.ip_address(sockaddr[0])
                        if addr.is_loopback or addr.is_private or addr.is_link_local:
                            raise ValueError(
                                f"MISP URL resolves to a non-routable address "
                                f"({sockaddr[0]}): SSRF protection"
                            )
                except socket.gaierror as exc:
                    raise ValueError(
                        f"MISP URL {self._misp_url!r}: DNS resolution failed — "
                        "cannot validate for SSRF. "
                        "Ensure the hostname resolves before starting the server."
                    ) from exc
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
