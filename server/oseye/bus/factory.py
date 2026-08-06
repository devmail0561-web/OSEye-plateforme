"""EventBus factory — selects implementation based on settings."""

from __future__ import annotations

from oseye.bus.interface import EventBus
from oseye.bus.memory_bus import InMemoryEventBus
from oseye.bus.redis_bus import RedisEventBus
from oseye.config import Settings


def create_bus(settings: Settings) -> EventBus:
    """Return the appropriate EventBus based on settings.

    Uses RedisEventBus when redis_url is set, InMemoryEventBus otherwise.
    """
    if settings.redis_url:
        return RedisEventBus(settings.redis_url)
    return InMemoryEventBus()
