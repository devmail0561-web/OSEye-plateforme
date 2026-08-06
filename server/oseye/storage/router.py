"""StorageRouter — routes writes to ClickHouse (high-volume) and PostgreSQL (relational)."""

from __future__ import annotations

from oseye.core.schema import UniversalEvent
from oseye.storage.interface import EventRepository


class StorageRouter:
    """Routes event writes to the appropriate backend(s).

    In dev mode (ch=None), all writes go to the single backend (SQLite or PostgreSQL).
    In production, events are written to ClickHouse for volume and PostgreSQL for UUID lookup.
    Non-event data (alerts, decisions, cases) always goes to PostgreSQL only.
    """

    def __init__(
        self,
        pg: EventRepository,
        ch: EventRepository | None = None,
    ) -> None:
        self._pg = pg
        self._ch = ch  # None in dev/sqlite mode

    async def insert_events(self, events: list[UniversalEvent]) -> None:
        """Write events to all configured backends."""
        if self._ch is not None:
            await self._ch.insert_batch(events)
        await self._pg.insert_batch(events)

    @property
    def pg(self) -> EventRepository:
        return self._pg

    @property
    def has_clickhouse(self) -> bool:
        return self._ch is not None
