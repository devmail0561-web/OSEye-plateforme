from __future__ import annotations

from typing import Protocol, runtime_checkable

from oseye.threat_intel.models import ThreatIntelReport


@runtime_checkable
class ThreatIntelProvider(Protocol):
    name: str

    async def lookup_ip(self, ip: str) -> ThreatIntelReport | None: ...

    async def lookup_hash(self, hash_value: str) -> ThreatIntelReport | None: ...

    async def close(self) -> None: ...

    def supports(self, indicator_type: str) -> bool:
        """Return True if this provider supports the given indicator type.

        TI-005: distinguishes "not supported" (None by design) from "error".
        Providers that do not override this method are assumed to support
        both "ip" and "hash" for backwards compatibility.
        """
        return True
