"""StorageRouter — routes writes to ClickHouse (high-volume) and PostgreSQL (relational)."""

from __future__ import annotations

import asyncio
import logging

from oseye.core.schema import UniversalEvent
from oseye.storage.interface import EventRepository

_log = logging.getLogger(__name__)


class StorageRouter:
    """Routes event writes to the appropriate backend(s).

    In dev mode (ch=None), all writes go to the single backend (SQLite or PostgreSQL).
    In production, events are written to ClickHouse for volume and PostgreSQL for UUID lookup.
    Non-event data (alerts, decisions, cases) always goes to PostgreSQL only.

    Source-of-truth policy (H-11):
      PostgreSQL is the authoritative source for all relational lookups (alerts,
      incidents, decisions, API). ClickHouse is the authoritative source for
      high-volume event queries and aggregations. Both writes are issued
      concurrently; a ClickHouse failure is non-fatal and logged as a divergence
      warning. A PostgreSQL failure is propagated as an exception.
    """

    def __init__(
        self,
        pg: EventRepository,
        ch: EventRepository | None = None,
    ) -> None:
        self._pg = pg
        self._ch = ch  # None in dev/sqlite mode

    async def insert_events(self, events: list[UniversalEvent]) -> None:
        """Write events to all configured backends.

        H-11: when ClickHouse is configured, both writes are issued concurrently
        via asyncio.gather so they do not block each other. PostgreSQL is the
        source of truth — its failure raises an exception. A ClickHouse-only
        failure is logged as a divergence warning and does not raise.
        """
        if self._ch is not None:
            ch_result, pg_result = await asyncio.gather(
                self._ch.insert_batch(events),
                self._pg.insert_batch(events),
                return_exceptions=True,
            )
            if isinstance(pg_result, BaseException):
                _log.error(
                    "StorageRouter: PostgreSQL insert failed (source of truth): %s", pg_result
                )
                raise pg_result
            if isinstance(ch_result, BaseException):
                _log.warning(
                    "StorageRouter: ClickHouse insert failed — divergence detected: %s",
                    ch_result,
                )
        else:
            await self._pg.insert_batch(events)

    @property
    def pg(self) -> EventRepository:
        return self._pg

    @property
    def has_clickhouse(self) -> bool:
        return self._ch is not None
