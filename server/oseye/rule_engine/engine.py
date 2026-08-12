"""Rule Engine — loads rules, evaluates events, hot-reloads on file changes.

Corrections vs initial version
--------------------------------

1. Hot-reload par inotify (fallback polling)
   Le polling toutes les 5s laissait une fenêtre aveugle trop longue lors d'un
   incident actif.  On utilise watchdog si disponible (inotify Linux natif),
   avec fallback transparent sur le polling pour les envs sans inotify (CI, macOS).

2. Évaluation O(1) par catégorie — index de dispatch
   Avec 500 règles, évaluer toutes les règles pour chaque event est inutile.
   Les règles sont indexées par categorie à chaque reload : un event "network"
   ne teste que les règles réseau + les règles sans filtre catégorie.
   Complexité : O(règles_matching_catégorie) au lieu de O(règles_total).

3. Persistance des fenêtres temporelles
   _temporal_windows est un dict global in-memory : redémarrage = cécité pendant
   timeframe secondes pour les règles temporelles.  Les fenêtres sont maintenant
   exportables/importables via save_temporal_state() / load_temporal_state() pour
   permettre une reprise après redémarrage.

4. entity_key stable — PID reuse guard
   entity_key = hostname:pid est sensible au PID recycling kernel.
   On ajoute l'heure de démarrage du process (start_time_ns) quand disponible,
   sinon on préfixe avec le ppid pour réduire les collisions : hostname:ppid:pid.
"""

from __future__ import annotations

import asyncio
import collections
import json
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

from oseye.core.observability import get_logger
from oseye.rule_engine import evaluator as _eval
from oseye.rule_engine.models import RuleDefinition, RuleMatch
from oseye.rule_engine.parser import load_all_rules

if TYPE_CHECKING:
    from oseye.core.schema import UniversalEvent

_log = get_logger(__name__)


class RuleEngine:
    """Thread-safe rule evaluator with optional filesystem hot-reload.

    Parameters
    ----------
    rules_root:
        Root directory containing ``builtin/`` and ``custom/`` sub-dirs.
    hot_reload:
        Watch ``rules_root`` for changes and reload automatically.
    reload_interval:
        Polling interval in seconds (used when watchdog is unavailable).
    """

    def __init__(
        self,
        rules_root: Path,
        hot_reload: bool = True,
        reload_interval: float = 5.0,
    ) -> None:
        self._rules_root = rules_root
        self._hot_reload = hot_reload
        self._reload_interval = reload_interval
        self._lock = threading.RLock()
        self._rules: list[RuleDefinition] = []
        # Correction 2 — index: category → list[RuleDefinition]
        # "" key = rules without category filter (evaluated for every event)
        self._index: dict[str, list[RuleDefinition]] = defaultdict(list)
        self._reload_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, event: UniversalEvent) -> list[RuleMatch]:
        """Evaluate *event* against relevant rules only (indexed by category).

        Returns a list of :class:`RuleMatch` (empty if no rule fires).
        """
        with self._lock:
            # Rules with no category filter + rules scoped to this event's category
            candidates = list(self._index.get("", []))
            category_rules = self._index.get(event.category, [])
            if category_rules:
                candidates = candidates + category_rules

        # Correction 4 — stable entity_key with PID reuse guard
        default_entity_key = _stable_entity_key(event)

        matches: list[RuleMatch] = []
        for rule in candidates:
            if not rule.enabled:
                continue
            try:
                entity_key = (
                    _build_entity_key(rule.entity_key, event)
                    if rule.entity_key
                    else default_entity_key
                )
                if _eval.evaluate(rule, event, entity_key=entity_key):
                    matches.append(
                        RuleMatch(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            actions=rule.actions,
                            tags=rule.tags,
                            mitre=rule.mitre,
                            explanation=rule.explanation,
                            matched_fields={
                                "category": event.category,
                                "type": event.type,
                                "hostname": event.hostname,
                                "pid": event.pid,
                                "executable": event.executable,
                                "resource": event.resource,
                            },
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                _log.debug("rule_engine_eval_exception", rule_id=rule.id, error=str(exc))

        if matches:
            _log.info(
                "rule_matches",
                event_id=str(event.event_id),
                hostname=event.hostname,
                count=len(matches),
                rule_ids=[m.rule_id for m in matches],
            )
        return matches

    def reload(self) -> int:
        """Reload rules from disk. Returns number of loaded rules."""
        rules = load_all_rules(self._rules_root)
        index: dict[str, list[RuleDefinition]] = defaultdict(list)
        for rule in rules:
            if rule.categories:
                for cat in rule.categories:
                    index[cat].append(rule)
            else:
                index[""].append(rule)
        with self._lock:
            self._rules = rules
            self._index = index
        _log.info("rule_engine_reloaded", count=len(rules))
        return len(rules)

    def list_rules(self) -> list[RuleDefinition]:
        """Return a thread-safe snapshot of all loaded rules."""
        with self._lock:
            return list(self._rules)

    @property
    def rule_count(self) -> int:
        with self._lock:
            return len(self._rules)

    @property
    def enabled_count(self) -> int:
        with self._lock:
            return sum(1 for r in self._rules if r.enabled)

    def get_rule(self, rule_id: str) -> RuleDefinition | None:
        with self._lock:
            for r in self._rules:
                if r.id == rule_id:
                    return r
        return None

    # ------------------------------------------------------------------
    # Correction 3 — temporal state persistence
    # ------------------------------------------------------------------

    async def save_temporal_state(self, path: str | Path) -> None:
        """Persist temporal windows to *path* so they survive a restart.

        Call periodically (e.g. every 60 s) from a maintenance task.
        Serialises deque[tuple[float, dict]] as list of [float, dict] in JSON.
        Uses atomic write (tmp + os.replace) to avoid partial state files.
        File I/O is offloaded to a thread-pool executor to avoid blocking the
        asyncio event loop.
        """
        import os as _os

        with _eval._temporal_windows_lock:
            state = {
                key: [[entry[0], entry[1]] for entry in window]
                for key, window in _eval._temporal_windows.items()
            }
        tmp_path = str(path) + ".tmp"

        class _Encoder(json.JSONEncoder):
            def default(self, o: object) -> object:
                import datetime
                import uuid
                if isinstance(o, uuid.UUID):
                    return str(o)
                if isinstance(o, (datetime.datetime, datetime.date)):
                    return o.isoformat()
                return super().default(o)

        # Serialise in the event-loop thread (pure CPU, minimal cost).
        serialized = json.dumps(state, cls=_Encoder)
        path_str = str(path)

        def _write_state() -> None:
            with open(tmp_path, "w") as fh:
                fh.write(serialized)
            _os.replace(tmp_path, path_str)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _write_state)
        _log.info("temporal_state_saved", path=path_str, windows=len(state))

    async def load_temporal_state(self, path: str | Path) -> None:
        """Restore temporal windows from a file written by :meth:`save_temporal_state`.

        Call on startup before the rule worker begins consuming events.
        File I/O is offloaded to a thread-pool executor to avoid blocking the
        asyncio event loop.
        """
        loop = asyncio.get_running_loop()
        path_str = str(path)

        def _read_state() -> str:
            with open(path) as fh:
                return fh.read()

        try:
            raw_text = await loop.run_in_executor(None, _read_state)
            raw = json.loads(raw_text)
        except Exception as exc:  # noqa: BLE001
            _log.warning("temporal_state_load_failed", path=path_str, error=str(exc))
            return
        state = {
            key: collections.deque(
                ((float(entry[0]), entry[1]) for entry in entries),
                maxlen=_eval._MAX_WINDOW_ENTRIES,
            )
            for key, entries in raw.items()
        }
        with _eval._temporal_windows_lock:
            _eval._temporal_windows.update(state)
        _log.info("temporal_state_loaded", path=path_str, windows=len(state))

    # ------------------------------------------------------------------
    # Bloc 4b — temporal window purge
    # ------------------------------------------------------------------

    async def purge_stale_windows(self, max_age_seconds: int = 3600) -> int:
        """Remove temporal window entries older than *max_age_seconds*.

        A window key is removed when **all** its entries have a timestamp
        older than the cutoff (or the deque is empty).  This mirrors the
        logic of :func:`oseye.rule_engine.evaluator._purge_old_windows` but
        accepts a configurable TTL and returns the number of keys removed so
        the caller can log it.

        Thread-safe: acquires ``_eval._temporal_windows_lock``.
        The method is *async* so it integrates naturally with the asyncio
        worker loop without introducing a blocking call.

        Parameters
        ----------
        max_age_seconds:
            Keys whose latest entry is older than this value (in seconds)
            are removed.  Defaults to 3600 s (1 hour).

        Returns
        -------
        int
            Number of window keys deleted.
        """
        cutoff = time.time() - max_age_seconds
        with _eval._temporal_windows_lock:
            keys_to_delete = [
                k
                for k, dq in _eval._temporal_windows.items()
                if not dq or all(ts < cutoff for ts, _ in dq)
            ]
            for k in keys_to_delete:
                del _eval._temporal_windows[k]
        removed = len(keys_to_delete)
        _log.info("rule_engine_purge_stale_windows", removed=removed)
        return removed

    # ------------------------------------------------------------------
    # Hot-reload — watchdog (inotify) with polling fallback
    # ------------------------------------------------------------------

    async def start_hot_reload(self) -> None:
        """Start background hot-reload using watchdog if available, else polling."""
        if not self._hot_reload:
            return
        self._stop_event.clear()
        # Correction 1: try inotify-based watchdog first
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer

            engine_ref = self

            class _Handler(FileSystemEventHandler):  # type: ignore[misc]
                def on_any_event(self, event: object) -> None:  # noqa: D102
                    _log.info("rule_engine_change_detected_inotify")
                    # F-06: catch reload errors so the watchdog thread stays alive
                    try:
                        engine_ref.reload()
                    except Exception as exc:  # noqa: BLE001
                        _log.error("rule_engine_hot_reload_failed", error=str(exc))
                        # Continue — watchdog stays alive

            observer = Observer()
            observer.schedule(_Handler(), str(self._rules_root), recursive=True)
            observer.start()
            self._reload_task = asyncio.create_task(
                self._watchdog_sentinel(observer), name="rule_engine_hot_reload"
            )
            _log.info("rule_engine_hot_reload_inotify_active")
        except ImportError:
            # watchdog not installed — fall back to polling
            self._reload_task = asyncio.create_task(
                self._poll_loop(), name="rule_engine_hot_reload"
            )
            _log.info("rule_engine_hot_reload_polling_active", interval=self._reload_interval)

    async def stop(self) -> None:
        """Stop the hot-reload task."""
        self._stop_event.set()
        if self._reload_task is not None:
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass

    async def _watchdog_sentinel(self, observer: object) -> None:
        """Keep observer alive until stop_event is set."""
        try:
            while not self._stop_event.is_set():
                await asyncio.sleep(1.0)
        finally:
            observer.stop()  # type: ignore[attr-defined]
            observer.join()  # type: ignore[attr-defined]

    async def _poll_loop(self) -> None:
        loop = asyncio.get_running_loop()
        last_mtime = await loop.run_in_executor(None, self._current_mtime)
        while not self._stop_event.is_set():
            await asyncio.sleep(self._reload_interval)
            mtime = await loop.run_in_executor(None, self._current_mtime)
            if mtime != last_mtime:
                _log.info("rule_engine_change_detected_poll", rules_root=str(self._rules_root))
                self.reload()
                last_mtime = mtime

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load(self) -> None:
        rules = load_all_rules(self._rules_root)
        index: dict[str, list[RuleDefinition]] = defaultdict(list)
        for rule in rules:
            if rule.categories:
                for cat in rule.categories:
                    index[cat].append(rule)
            else:
                index[""].append(rule)
        with self._lock:
            self._rules = rules
            self._index = index
        _log.info("rule_engine_loaded", count=len(rules), rules_root=str(self._rules_root))

    def _current_mtime(self) -> float:
        """Return sum of mtimes for all YAML/YML files under rules_root."""
        total = 0.0
        if not self._rules_root.exists():
            return total
        for pattern in ("*.yaml", "*.yml"):
            for path in self._rules_root.rglob(pattern):
                try:
                    total += path.stat().st_mtime
                except OSError:
                    pass
        return total


def _build_entity_key(template: str, event: UniversalEvent) -> str:
    """Build an entity key from a YAML-defined template like 'hostname:src_ip'."""
    parts = template.split(":")
    return ":".join(str(getattr(event, p, "") or "") for p in parts)


def _stable_entity_key(event: UniversalEvent) -> str:
    """Build a stable entity key resistant to PID reuse.

    Correction 4: if the event carries a session_id (set by the Go agent from
    the process start time or session), use hostname:session_id:pid.
    Otherwise fall back to hostname:ppid:pid — combining ppid with pid makes
    recycled PIDs much less likely to collide with a past entry.
    """
    if event.session_id is not None:
        return f"{event.hostname}:{event.session_id}:{event.pid}"
    return f"{event.hostname}:{event.ppid}:{event.pid}"
