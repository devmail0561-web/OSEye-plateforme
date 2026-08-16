"""TI worker — enriches alerts with Threat Intelligence data.

Subscribes to ``alerts:enrichment``.
Publishes ``alerts:enriched`` with a JSON TI enrichment payload.

Message format consumed (alerts:enrichment)::

    {
        "alert_id": "<uuid>",
        "indicators": {"ips": ["1.2.3.4"], "hashes": ["abc123..."]}
    }

Message format published (alerts:enriched)::

    {
        "alert_id": "<uuid>",
        "ti_score": 75.0,
        "malicious": true,
        "tags": ["brute-force", "ssh"]
    }
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.storage.repositories.alerts import SQLAlertRepository
    from oseye.threat_intel.client import ThreatIntelClient

_log = get_logger(__name__)

CONSUME_TOPIC = "alerts:enrichment"
PUBLISH_TOPIC = "alerts:enriched"


class TIWorker:
    """Consumes alerts:enrichment, performs TI lookups, publishes alerts:enriched.

    Parameters
    ----------
    bus:        EventBus instance.
    ti_client:  Configured ThreatIntelClient.
    alert_repo: Used to update ti_triggered on the alert.
    stop_event: Optional asyncio.Event — worker exits when set.
    """

    def __init__(
        self,
        bus: EventBus,
        ti_client: ThreatIntelClient,
        alert_repo: SQLAlertRepository,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        self._bus = bus
        self._ti_client = ti_client
        self._alert_repo = alert_repo
        self._stop_event = stop_event or asyncio.Event()
        self._total_processed = 0
        self._total_malicious = 0

    async def run(self) -> None:
        """Main loop — runs until stop_event is set or task is cancelled."""
        _log.info("ti_worker_started", topic=CONSUME_TOPIC)

        try:
            async for message in await self._bus.subscribe(CONSUME_TOPIC):
                try:
                    payload = json.loads(message)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("ti_worker_parse_error", error=str(exc))
                    continue

                await self._process(payload)

                if self._stop_event.is_set():
                    break
        finally:
            _log.info(
                "ti_worker_stopped",
                processed=self._total_processed,
                malicious=self._total_malicious,
            )

    async def _process(self, payload: dict[str, object]) -> None:
        from typing import cast as _cast
        alert_id: str = str(payload.get("alert_id", ""))
        indicators: dict[str, object] = _cast(dict[str, object], payload.get("indicators", {}))
        ips: list[str] = _cast(list[str], indicators.get("ips", []))
        hashes: list[str] = _cast(list[str], indicators.get("hashes", []))

        if not alert_id:
            _log.warning("ti_worker_missing_alert_id", payload=payload)
            return

        max_score = 0.0
        is_malicious = False
        all_tags: list[str] = []

        # Look up all IPs
        for ip in ips:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                _log.warning("ti_worker_invalid_ip", ip=ip)
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                _log.debug("ti_worker_ip_skipped", ip=ip, reason="private/loopback/link-local")
                continue
            try:
                report = await self._ti_client.lookup(ip, "ip")
                if report.max_score > max_score:
                    max_score = report.max_score
                if report.malicious:
                    is_malicious = True
                for tag in report.tags:
                    if tag not in all_tags:
                        all_tags.append(tag)
            except Exception as exc:  # noqa: BLE001
                _log.warning("ti_worker_lookup_error", ip=ip, error=str(exc))

        # Look up all hashes
        for hash_value in hashes:
            try:
                report = await self._ti_client.lookup(hash_value, "hash")
                if report.max_score > max_score:
                    max_score = report.max_score
                if report.malicious:
                    is_malicious = True
                for tag in report.tags:
                    if tag not in all_tags:
                        all_tags.append(tag)
            except Exception as exc:  # noqa: BLE001
                _log.warning("ti_worker_lookup_error", hash=hash_value, error=str(exc))

        self._total_processed += 1
        if is_malicious:
            self._total_malicious += 1

        # Update alert in storage if malicious
        if is_malicious:
            try:
                from uuid import UUID

                alert = await self._alert_repo.get(UUID(alert_id))
                if alert is not None:
                    alert.ti_triggered = True
                    await self._alert_repo.update(alert)
                    _log.info(
                        "ti_worker_alert_updated",
                        alert_id=alert_id,
                        ti_score=max_score,
                    )
            except Exception as exc:  # noqa: BLE001
                _log.error("ti_worker_alert_update_error", alert_id=alert_id, error=str(exc))

        # Publish enrichment result
        enriched_payload = json.dumps(
            {
                "alert_id": alert_id,
                "ti_score": max_score,
                "malicious": is_malicious,
                "tags": all_tags,
            }
        ).encode()

        try:
            await self._bus.publish(PUBLISH_TOPIC, enriched_payload)
        except Exception as exc:  # noqa: BLE001
            _log.error("ti_worker_publish_error", alert_id=alert_id, error=str(exc))

        _log.info(
            "ti_worker_enriched",
            alert_id=alert_id,
            ti_score=max_score,
            malicious=is_malicious,
            tags=all_tags,
        )
