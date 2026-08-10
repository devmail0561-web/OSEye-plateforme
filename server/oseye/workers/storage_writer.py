"""Storage writer worker.

Subscribes to ``events:normalized`` on the event bus and batch-inserts
UniversalEvents into the database every ``flush_interval_ms`` milliseconds
or when the batch reaches ``batch_max_size`` events.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger
from oseye.core.schema import UniversalEvent

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.storage.repositories.events import SQLEventRepository

_logger = get_logger(__name__)

TOPIC = "events:normalized"

# F-05: maximum number of consecutive flush failures before the accumulated
# batch is dropped (rather than growing without bound).
MAX_FLUSH_FAILURES = 5


class StorageWriter:
    """Consumes normalised events from the bus and persists them in batches."""

    def __init__(
        self,
        bus: EventBus,
        repo: SQLEventRepository,
        flush_interval_ms: int = 500,
        batch_max_size: int = 500,
    ) -> None:
        self._bus = bus
        self._repo = repo
        self._flush_interval = flush_interval_ms / 1000.0
        self._batch_max_size = batch_max_size
        self._batch: list[UniversalEvent] = []
        self._total_written = 0
        # F-05: track consecutive flush failures to prevent unbounded accumulation.
        self._consecutive_failures: int = 0

    async def run(self, *, stop_event: asyncio.Event | None = None) -> None:
        """Main loop — runs until *stop_event* is set or task is cancelled.

        A periodic flush timer runs as a sibling task so that buffered events
        are persisted even when no new messages arrive for an extended period.
        """
        _logger.info("storage_writer_started", topic=TOPIC)

        async def _timer_flush() -> None:
            # BUG-011: check stop_event BEFORE sleeping so the timer exits
            # promptly when the writer is asked to stop, rather than waiting
            # for the full flush interval to elapse first.
            while stop_event is None or not stop_event.is_set():
                await asyncio.sleep(self._flush_interval)
                await self._flush()

        flush_task = asyncio.create_task(_timer_flush(), name="storage_writer_flush_timer")

        try:
            async for message in await self._bus.subscribe(TOPIC):
                try:
                    # Fast path: model_validate_json uses Pydantic v2 Rust parser (~2× faster).
                    event = UniversalEvent.model_validate_json(message)
                    self._batch.append(event)
                except Exception:  # noqa: BLE001
                    # Slow path: deserialise to dict first to inject a missing event_id.
                    try:
                        data = json.loads(message)
                        if not data.get("event_id"):
                            data["event_id"] = str(uuid.uuid4())
                        event = UniversalEvent.model_validate(data)
                        self._batch.append(event)
                    except Exception as exc:  # noqa: BLE001
                        _logger.warning("storage_writer_parse_error", error=str(exc))
                        continue

                if len(self._batch) >= self._batch_max_size:
                    await self._flush()

                if stop_event is not None and stop_event.is_set():
                    break
        finally:
            flush_task.cancel()
            await asyncio.gather(flush_task, return_exceptions=True)
            await self._flush()
            _logger.info("storage_writer_stopped", total_written=self._total_written)

    async def _flush(self) -> None:
        if not self._batch:
            return
        batch = self._batch
        self._batch = []
        try:
            await self._repo.insert_batch(batch)
            self._total_written += len(batch)
            self._consecutive_failures = 0
            _logger.info("storage_writer_flushed", count=len(batch))
        except Exception as exc:  # noqa: BLE001
            self._consecutive_failures += 1
            if self._consecutive_failures >= MAX_FLUSH_FAILURES:
                # F-05: persistent DB failure — drop the batch to prevent
                # unbounded memory accumulation, and route to dead-letter topic.
                _logger.error(
                    "storage_writer_batch_dropped",
                    error=str(exc),
                    dropped=len(batch),
                    consecutive_failures=self._consecutive_failures,
                )
                try:
                    dead_letter_payload = json.dumps(
                        {
                            "reason": "storage_flush_failed",
                            "dropped_count": len(batch),
                            "consecutive_failures": self._consecutive_failures,
                            "error": str(exc),
                        }
                    ).encode()
                    await self._bus.publish("events:dead_letter", dead_letter_payload)
                except Exception as dl_exc:  # noqa: BLE001
                    _logger.error("storage_writer_dead_letter_failed", error=str(dl_exc))
                self._consecutive_failures = 0
            else:
                # Transient error — re-queue for next flush attempt
                self._batch = batch + self._batch
                _logger.error(
                    "storage_writer_flush_error",
                    error=str(exc),
                    requeued=len(batch),
                    consecutive_failures=self._consecutive_failures,
                )
