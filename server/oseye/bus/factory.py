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


def create_worker_bus(settings: Settings, shared_bus: EventBus, group: str) -> EventBus:
    """Return a bus for a specific worker consumer group.

    Redis: dedicated instance with its own consumer group so every worker
    receives ALL messages on the topic (true fan-out via independent groups).
    InMemory: returns shared_bus unchanged — InMemoryEventBus already fans
    out to every subscriber via independent queues.
    """
    if settings.redis_url:
        return RedisEventBus(settings.redis_url, consumer_group=group)
    return shared_bus
