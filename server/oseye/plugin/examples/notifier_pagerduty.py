from __future__ import annotations

import logging

from oseye_sdk.event import Event
from oseye_sdk.plugin import ExporterPlugin

logger = logging.getLogger(__name__)


class PagerDutyNotifier(ExporterPlugin):
    """Send high/critical events to PagerDuty (stub).

    Production implementation would POST to the PagerDuty Events API v2
    using a routing_key loaded from plugin configuration.
    """

    name = "notifier_pagerduty"
    description = "Send high/critical events to PagerDuty (stub)"

    def on_start(self) -> None:
        # In prod: load routing_key from config
        logger.info("PagerDutyNotifier started (stub mode)")

    def on_stop(self) -> None:
        logger.info("PagerDutyNotifier stopped")

    def export(self, event: Event) -> None:
        if event.severity in ("high", "critical"):
            # In prod: POST to PagerDuty Events API v2
            # payload = {
            #     "routing_key": self._routing_key,
            #     "event_action": "trigger",
            #     "payload": {
            #         "summary": f"[{event.severity.upper()}] {event.type} on {event.hostname}",
            #         "source": event.hostname,
            #         "severity": event.severity,
            #         "custom_details": {
            #             "event_id": event.event_id,
            #             "category": event.category,
            #             "process": event.process_name,
            #         },
            #     },
            # }
            # httpx.post("https://events.pagerduty.com/v2/enqueue", json=payload)
            logger.info(
                "PagerDutyNotifier: would send event %s (severity=%s) to PagerDuty",
                event.event_id,
                event.severity,
            )
