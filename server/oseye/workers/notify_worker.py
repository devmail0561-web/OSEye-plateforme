"""Notification worker — consumes notifications:pending and dispatches to plugin hooks.

Subscribes to ``notifications:pending`` (published by ActionExecutor for every
NOTIFY decision) and logs each notification.  Plugin hooks (ExporterPlugin,
Slack, webhook…) are invoked via PluginManager when registered.

Message format consumed (notifications:pending)::

    {
        "decision_id": "<uuid>",
        "entity_id":   "<hostname>",
        "final_score": <float>,
        "explanation": "<str>",
        "created_at":  "<iso8601>"
    }
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus

_log = get_logger(__name__)

CONSUME_TOPIC = "notifications:pending"


class NotificationWorker:
    """Consumes notifications:pending and dispatches to plugin hooks.

    Parameters
    ----------
    bus:        EventBus instance.
    stop_event: Optional asyncio.Event — worker exits when set.
    """

    def __init__(
        self,
        bus: EventBus,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        self._bus = bus
        self._stop_event = stop_event or asyncio.Event()

    async def run(self) -> None:
        """Main loop — runs until stop_event is set or task is cancelled."""
        _log.info("notification_worker_started", topic=CONSUME_TOPIC)

        try:
            async for message in await self._bus.subscribe(CONSUME_TOPIC):
                try:
                    payload = json.loads(message)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("notification_worker_parse_error", error=str(exc))
                    continue

                await self._process(payload)

                if self._stop_event.is_set():
                    break
        finally:
            _log.info("notification_worker_stopped")

    async def _process(self, payload: dict) -> None:
        decision_id = payload.get("decision_id", "")
        decision_type = payload.get("decision_type", "NOTIFY")
        hostname = payload.get("entity_id", "")

        _log.info(
            "notification_received",
            decision_id=decision_id,
            decision_type=decision_type,
            hostname=hostname,
        )
        # TODO: appeler les hooks plugin (ExporterPlugin, Slack, webhook) via PluginManager
