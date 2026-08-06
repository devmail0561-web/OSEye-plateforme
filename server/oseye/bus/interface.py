"""Event bus Protocol — all bus implementations must satisfy this interface."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Protocol, runtime_checkable


@runtime_checkable
class EventBus(Protocol):
    """Async publish/subscribe event bus.

    Topics follow the pattern:
      events:raw:{agent_id}     — raw events from a specific agent
      events:normalized         — normalised UniversalEvents
      events:enriched           — TI-enriched events
      analysis:rules:{host}     — rule engine matches
      analysis:ml               — ML anomaly scores
      analysis:correlated       — correlated incidents
      decisions:completed       — completed decisions
      decisions:pending         — decisions awaiting human approval
      policy:push:{agent_id}    — SurveillanceProfile push to agent
    """

    async def publish(self, topic: str, message: bytes) -> None:
        """Publish a message to a topic."""
        ...

    async def subscribe(self, topic: str) -> AsyncGenerator[bytes, None]:
        """Yield messages from a topic, blocking until each arrives."""
        ...

    async def subscribe_pattern(self, pattern: str) -> AsyncGenerator[tuple[str, bytes], None]:
        """Yield (topic, message) pairs for all topics matching the glob pattern."""
        ...
