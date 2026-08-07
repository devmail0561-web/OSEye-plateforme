"""Rule Engine — loads rules, evaluates events, hot-reloads on file changes."""

from __future__ import annotations

import asyncio
import threading
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
        Polling interval in seconds when ``hot_reload=True``.
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
        self._reload_task: asyncio.Task[None] | None = None
        self._stop_event = asyncio.Event()
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self, event: UniversalEvent) -> list[RuleMatch]:
        """Evaluate *event* against all enabled rules.

        Returns a list of :class:`RuleMatch` (empty if no rule fires).
        """
        matches: list[RuleMatch] = []
        with self._lock:
            rules = list(self._rules)

        for rule in rules:
            if not rule.enabled:
                continue
            try:
                if _eval.evaluate(rule, event):
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
        """Reload rules from disk.  Returns number of loaded rules."""
        rules = load_all_rules(self._rules_root)
        with self._lock:
            self._rules = rules
        _log.info("rule_engine_reloaded", count=len(rules))
        return len(rules)

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
    # Hot-reload (async polling — no inotify dependency)
    # ------------------------------------------------------------------

    async def start_hot_reload(self) -> None:
        """Start background polling task for hot-reload."""
        if not self._hot_reload:
            return
        self._stop_event.clear()
        self._reload_task = asyncio.create_task(self._poll_loop(), name="rule_engine_hot_reload")

    async def stop(self) -> None:
        """Stop the hot-reload task."""
        self._stop_event.set()
        if self._reload_task is not None:
            self._reload_task.cancel()
            try:
                await self._reload_task
            except asyncio.CancelledError:
                pass

    async def _poll_loop(self) -> None:
        last_mtime = self._current_mtime()
        while not self._stop_event.is_set():
            await asyncio.sleep(self._reload_interval)
            mtime = self._current_mtime()
            if mtime != last_mtime:
                _log.info("rule_engine_change_detected", rules_root=str(self._rules_root))
                self.reload()
                last_mtime = mtime

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load(self) -> None:
        rules = load_all_rules(self._rules_root)
        with self._lock:
            self._rules = rules
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
