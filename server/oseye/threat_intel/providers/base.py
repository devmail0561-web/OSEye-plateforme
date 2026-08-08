from __future__ import annotations

from typing import Protocol, runtime_checkable

from oseye.threat_intel.models import ThreatIntelReport


@runtime_checkable
class ThreatIntelProvider(Protocol):
    name: str

    async def lookup_ip(self, ip: str) -> ThreatIntelReport | None: ...

    async def lookup_hash(self, hash_value: str) -> ThreatIntelReport | None: ...

    async def close(self) -> None: ...
