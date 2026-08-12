"""Dev worker runner — starts all background workers with asyncio.gather.

Usage (dev):
    python -m oseye.workers.runner

In production the workers run inside the same process as the server,
started from ``oseye.main`` lifespan.
"""

from __future__ import annotations

import asyncio
import socket

from oseye.bus.factory import create_bus
from oseye.config import Settings
from oseye.core.observability import get_logger
from oseye.normalizer.engine import NormalizerEngine
from oseye.storage.backends.sqlite import SQLiteBackend
from oseye.storage.repositories.alerts import SQLAlertRepository
from oseye.storage.repositories.events import SQLEventRepository
from oseye.workers.rule_worker import RuleWorker
from oseye.workers.storage_writer import StorageWriter

_logger = get_logger(__name__)


async def run_workers(settings: Settings) -> None:
    """Initialise all resources and run workers concurrently."""
    bus = create_bus(settings)

    backend = SQLiteBackend(settings.db_url)
    await backend.init()
    repo = SQLEventRepository(backend.session_factory)

    normalizer = NormalizerEngine(bus=bus, hostname=socket.gethostname())
    writer = StorageWriter(
        bus=bus,
        repo=repo,
        flush_interval_ms=settings.batch_flush_interval_ms,
        batch_max_size=settings.batch_max_size,
    )
    alert_repo = SQLAlertRepository(backend.session_factory)
    rule_worker = RuleWorker(bus=bus, alert_repo=alert_repo, hot_reload=False)

    stop = asyncio.Event()
    _logger.info("workers_starting")

    async def _normalizer_loop() -> None:
        """Subscribe to raw events and pass them through the normalizer."""
        async for topic, message in await bus.subscribe_pattern("events:raw:*"):
            # topic format: events:raw:{agent_id}
            parts = topic.split(":")
            agent_id = parts[2] if len(parts) >= 3 else "unknown"
            await normalizer.process(
                raw_payload=message,
                source="procfs",
                os_name="linux",
                agent_id=agent_id,
            )
            if stop.is_set():
                break

    try:
        await asyncio.gather(
            _normalizer_loop(),
            writer.run(stop_event=stop),
            rule_worker.run(stop_event=stop),
        )
    except asyncio.CancelledError:
        stop.set()
        _logger.info("workers_cancelled")


def main() -> None:
    settings = Settings()
    asyncio.run(run_workers(settings))


if __name__ == "__main__":
    main()
