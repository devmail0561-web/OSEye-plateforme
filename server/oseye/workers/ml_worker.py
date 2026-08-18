"""ML worker — scores every normalised event and checkpoints models periodically.

Subscribes to ``events:normalized``.
Publishes ``analysis:ml`` with a JSON payload containing the ML score.
Checkpoints the anomaly detector + MITRE classifier to disk every
``checkpoint_interval_s`` seconds via a background asyncio task.

Message format consumed (events:normalized)::

    <UniversalEvent JSON>

Message format published (analysis:ml)::

    {
        "event_id":  "<uuid>",
        "hostname":  "<str>",
        "category":  "<str>",
        "ml_score":  42.7          // float [0, 100]
    }
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger
from oseye.core.schema import UniversalEvent

if TYPE_CHECKING:
    from oseye.bus.interface import EventBus
    from oseye.ml_engine.ab_test import ABTestSession
    from oseye.ml_engine.engine import MLEngine
    from oseye.storage.repositories.events import SQLEventRepository

_log = get_logger(__name__)

CONSUME_TOPIC = "events:normalized"
PUBLISH_TOPIC = "analysis:ml"
_DEFAULT_CHECKPOINT_INTERVAL_S = 300  # 5 minutes
# Fallback path — production must pass settings.ml_checkpoint_path explicitly.
# /tmp is intentionally avoided; callers should always supply the path from Settings.
_DEFAULT_CHECKPOINT_PATH = Path("/var/lib/oseye/ml_checkpoint.pkl")


class MLWorker:
    """Scores normalised events with the ML engine and checkpoints models.

    Parameters
    ----------
    bus:                     EventBus instance.
    engine:                  MLEngine singleton shared with DecisionWorker.
    checkpoint_path:         File path for model persistence (anomaly + classifier).
    checkpoint_interval_s:   Seconds between periodic checkpoint saves.
                             0 disables the periodic task (checkpoint-on-stop only).
    stop_event:              Optional asyncio.Event — worker exits when set.
    """

    def __init__(
        self,
        bus: EventBus,
        engine: MLEngine,
        checkpoint_path: Path | None = None,
        checkpoint_interval_s: float = _DEFAULT_CHECKPOINT_INTERVAL_S,
        stop_event: asyncio.Event | None = None,
        event_repo: SQLEventRepository | None = None,
        ab_session: ABTestSession | None = None,
    ) -> None:
        self._bus = bus
        self._engine = engine
        self._checkpoint_path = checkpoint_path or _DEFAULT_CHECKPOINT_PATH
        self._checkpoint_interval_s = checkpoint_interval_s
        self._stop_event = stop_event or asyncio.Event()
        self._event_repo = event_repo
        self._ab_session = ab_session
        self._total_scored = 0
        self._total_published = 0

    async def run(self) -> None:
        """Main loop — runs until stop_event is set or task is cancelled.

        Starts a background checkpoint task (if interval > 0) that saves the
        model state every ``checkpoint_interval_s`` seconds regardless of whether
        the event stream is active.  This ensures the baseline survives crashes.
        """
        self._try_load_checkpoint()
        _log.info(
            "ml_worker_started",
            topic=CONSUME_TOPIC,
            checkpoint_path=str(self._checkpoint_path),
            checkpoint_interval_s=self._checkpoint_interval_s,
        )

        checkpoint_task: asyncio.Task[None] | None = None
        if self._checkpoint_interval_s > 0:
            checkpoint_task = asyncio.create_task(self._periodic_checkpoint())

        try:
            async for message in await self._bus.subscribe(CONSUME_TOPIC):
                try:
                    event = UniversalEvent.model_validate_json(message)
                except Exception as exc:  # noqa: BLE001
                    _log.warning("ml_worker_parse_error", error=str(exc))
                    continue

                await self._process(event)

                if self._stop_event.is_set():
                    break
        finally:
            if checkpoint_task is not None:
                checkpoint_task.cancel()
                try:
                    await checkpoint_task
                except asyncio.CancelledError:
                    pass
            self._try_save_checkpoint()
            _log.info(
                "ml_worker_stopped",
                scored=self._total_scored,
                published=self._total_published,
            )

    async def _periodic_checkpoint(self) -> None:
        """Save the model state every checkpoint_interval_s seconds."""
        while True:
            await asyncio.sleep(self._checkpoint_interval_s)
            await asyncio.get_running_loop().run_in_executor(None, self._try_save_checkpoint)

    async def _process(self, event: UniversalEvent) -> None:
        # A/B test active: score_event internally scores both champion and
        # challenger and returns the authoritative champion score.
        loop = asyncio.get_running_loop()
        if self._ab_session is not None:
            try:
                ml_score = await loop.run_in_executor(
                    None, self._ab_session.score_event, event
                )
            except Exception as exc:  # noqa: BLE001
                _log.debug("ml_worker_ab_score_error", error=str(exc))
                ml_score = await loop.run_in_executor(
                    None, self._engine.score_event, event
                )
        else:
            ml_score = await loop.run_in_executor(None, self._engine.score_event, event)
        self._total_scored += 1

        payload = json.dumps(
            {
                "event_id": str(event.event_id),
                "hostname": event.hostname,
                "category": event.category,
                "ml_score": round(ml_score, 3),
            }
        ).encode()

        try:
            await self._bus.publish(PUBLISH_TOPIC, payload)
            self._total_published += 1
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "ml_worker_publish_error",
                event_id=str(event.event_id),
                error=str(exc),
            )

        # Persist ml_score in EventRow so it's queryable via the API.
        if self._event_repo is not None and ml_score > 0.0:
            try:
                await self._event_repo.update_ml_score(event.event_id, round(ml_score, 3))
            except Exception as exc:  # noqa: BLE001
                _log.debug("ml_worker_score_persist_error", event_id=str(event.event_id), error=str(exc))  # noqa: E501

    def checkpoint(self) -> None:
        """Save the model state to disk immediately (idempotent, non-async)."""
        self._try_save_checkpoint()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _try_save_checkpoint(self) -> None:
        try:
            self._checkpoint_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._engine.save_checkpoint(self._checkpoint_path)
            _log.info("ml_worker_checkpoint_saved", path=str(self._checkpoint_path))
        except Exception as exc:  # noqa: BLE001
            _log.warning("ml_worker_checkpoint_save_error", error=str(exc))

    def _try_load_checkpoint(self) -> None:
        if not self._checkpoint_path.exists():
            _log.info("ml_worker_no_checkpoint", path=str(self._checkpoint_path))
            return
        try:
            self._engine.load_checkpoint(self._checkpoint_path)
            _log.info(
                "ml_worker_checkpoint_loaded",
                path=str(self._checkpoint_path),
                models=self._engine.model_count,
            )
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "ml_worker_checkpoint_load_error",
                path=str(self._checkpoint_path),
                error=str(exc),
            )
