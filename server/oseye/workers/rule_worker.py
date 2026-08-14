"""Rule worker — consumes normalized events and publishes rule matches.

Subscribes to ``events:normalized``.
Publishes ``analysis:rules:{hostname}`` with a JSON RuleMatch payload.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger
from oseye.core.schema import Alert, UniversalEvent
from oseye.rule_engine import RuleEngine

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.ml_engine.engine import MLEngine
    from oseye.rule_engine.models import RuleMatch
    from oseye.storage.repositories.alerts import SQLAlertRepository

_log = get_logger(__name__)

CONSUME_TOPIC = "events:normalized"
PUBLISH_TOPIC_PREFIX = "analysis:rules"

_DEFAULT_RULES_ROOT = Path(__file__).parent.parent.parent.parent / "rules"


class RuleWorker:
    """Evaluates normalized events against all enabled rules.

    Parameters
    ----------
    bus:        EventBus instance.
    alert_repo: Where to persist generated alerts.
    rules_root: Directory with ``builtin/`` and ``custom/`` sub-dirs.
    hot_reload: Reload rules when YAML files change.
    """

    def __init__(
        self,
        bus: EventBus,
        alert_repo: SQLAlertRepository,
        rules_root: Path | None = None,
        hot_reload: bool = True,
        ml_engine: MLEngine | None = None,
    ) -> None:
        self._bus = bus
        self._alert_repo = alert_repo
        root = rules_root or _DEFAULT_RULES_ROOT
        self._engine = RuleEngine(rules_root=root, hot_reload=hot_reload)
        self._ml_engine = ml_engine
        self._total_evaluated = 0
        self._total_matches = 0
        self._total_alerts = 0

    async def run(self, *, stop_event: asyncio.Event | None = None) -> None:
        """Main loop — runs until *stop_event* is set or task is cancelled."""
        await self._engine.start_hot_reload()
        _log.info(
            "rule_worker_started",
            topic=CONSUME_TOPIC,
            rules=self._engine.rule_count,
            enabled=self._engine.enabled_count,
        )

        async def _periodic_purge() -> None:
            while not (stop_event is not None and stop_event.is_set()):
                await asyncio.sleep(600)  # 10 minutes
                try:
                    removed = await self._engine.purge_stale_windows()
                    _log.info("rule_engine_periodic_purge", removed=removed)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("rule_engine_purge_error", error=str(exc))

        purge_task = asyncio.create_task(_periodic_purge())
        try:
            async for message in await self._bus.subscribe(CONSUME_TOPIC):
                try:
                    event = UniversalEvent.model_validate_json(message)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("rule_worker_parse_error", error=str(exc))
                    continue

                self._total_evaluated += 1
                matches = self._engine.evaluate(event)
                if matches:
                    self._total_matches += len(matches)
                    await self._handle_matches(event, matches)

                if stop_event is not None and stop_event.is_set():
                    break
        finally:
            purge_task.cancel()
            try:
                await purge_task
            except asyncio.CancelledError:
                pass
            await self._engine.stop()
            _log.info(
                "rule_worker_stopped",
                evaluated=self._total_evaluated,
                matches=self._total_matches,
                alerts=self._total_alerts,
            )

    async def _handle_matches(
        self,
        event: UniversalEvent,
        matches: list[RuleMatch],
    ) -> None:
        for match in matches:
            # Publish match to bus for downstream consumers (correlation etc.)
            topic = f"{PUBLISH_TOPIC_PREFIX}:{event.hostname}"
            payload = {
                "rule_id": match.rule_id,
                "rule_name": match.rule_name,
                "severity": match.severity,
                "actions": match.actions,
                "tags": match.tags,
                "mitre": match.mitre,
                "explanation": match.explanation,
                "event_id": str(event.event_id),
                "hostname": event.hostname,
                "matched_fields": match.matched_fields,
            }
            # F-04: a single publish failure must not abort the remaining matches
            try:
                await self._bus.publish(topic, json.dumps(payload).encode())
            except Exception as e:  # noqa: BLE001
                _log.error(
                    "rule_worker_publish_error",
                    rule_id=match.rule_id,
                    topic=topic,
                    error=str(e),
                )
                continue

            # Create alert in storage if ALERT action is requested
            if "ALERT" in match.actions:
                await self._create_alert(event, match)

    async def _create_alert(self, event: UniversalEvent, match: RuleMatch) -> None:
        now = datetime.now(tz=UTC)
        severity = match.severity if match.severity != "info" else "low"
        alert = Alert(
            alert_id=uuid.uuid4(),
            created_at=now,
            updated_at=now,
            severity=severity,  # type: ignore[arg-type]
            status="open",
            rule_id=match.rule_id,
            ml_triggered=False,
            ti_triggered=False,
            entity_id=f"{event.hostname}:{event.pid}",
            hostname=event.hostname,
            trigger_event_id=event.event_id,
            related_event_ids=[],
            title=match.rule_name,
            description=match.explanation,
            mitre_techniques=match.mitre,
            dst_ip=event.dst_ip,
            pid=event.pid if event.pid else None,
            process_name=event.process_name,
        )
        try:
            await self._alert_repo.create(alert)
            self._total_alerts += 1
            _log.info(
                "alert_created",
                alert_id=str(alert.alert_id),
                rule_id=match.rule_id,
                hostname=event.hostname,
                severity=severity,
            )
        except Exception as exc:  # noqa: BLE001
            _log.error("alert_create_error", rule_id=match.rule_id, error=str(exc))
            return

        # Feedback loop: train ML classifier on confirmed positives (rule matches).
        # W-08: learn_from_alert() is CPU-bound/synchronous — run in a thread executor
        # so it does not block the asyncio event loop.
        if self._ml_engine is not None and match.mitre:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None,
                    self._ml_engine.learn_from_alert,
                    event,
                    list(match.mitre),
                )
            except Exception as exc:  # noqa: BLE001
                _log.debug("ml_learn_from_alert_error", error=str(exc))

        # F-01: ALWAYS publish alerts:created so CorrelationWorker and DecisionWorker
        # receive non-network alerts (filesystem, process, privilege escalation, etc.).
        try:
            await self._bus.publish(
                "alerts:created",
                json.dumps({"alert_id": str(alert.alert_id)}).encode(),
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "alerts_created_publish_error",
                alert_id=str(alert.alert_id),
                error=str(exc),
            )

        # Publish to TI enrichment pipeline if there are network indicators (optional).
        indicators: dict[str, list[str]] = {"ips": [], "hashes": []}
        if event.dst_ip:
            indicators["ips"].append(event.dst_ip)
        if event.src_ip:
            indicators["ips"].append(event.src_ip)
        if indicators["ips"] or indicators["hashes"]:
            try:
                await self._bus.publish(
                    "alerts:enrichment",
                    json.dumps(
                        {"alert_id": str(alert.alert_id), "indicators": indicators}
                    ).encode(),
                )
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "enrichment_publish_error",
                    alert_id=str(alert.alert_id),
                    error=str(exc),
                )
