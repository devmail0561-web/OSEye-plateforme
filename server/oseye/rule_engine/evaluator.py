"""Safe condition evaluator for OSEye rule engine.

Evaluates rule conditions against a UniversalEvent using a restricted
Python expression sandbox.  Supports:
  - Standard comparisons, boolean logic, membership (in / not in)
  - String methods: .startswith(), .endswith(), ``contains`` keyword
  - Regex: re.match(r"...", event.field)
  - Temporal aggregation: count_events("filter_expr", seconds) > N
"""

from __future__ import annotations

import ast
import collections
import re
import threading
import time
from typing import TYPE_CHECKING, Any

from oseye.core.observability import get_logger

if TYPE_CHECKING:
    from oseye.core.schema import UniversalEvent
    from oseye.rule_engine.models import RuleDefinition

_log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Temporal window store — keyed by (rule_id, entity_key)
# ---------------------------------------------------------------------------

# Deque of (timestamp_float, event_snapshot_dict) per window key
_temporal_windows: dict[str, collections.deque[tuple[float, dict[str, Any]]]] = {}
_MAX_WINDOW_ENTRIES = 10_000  # safety cap per window
_temporal_windows_lock = threading.Lock()
_record_count = 0  # global call counter for periodic purge


def _window_key(rule_id: str, entity_key: str) -> str:
    return f"{rule_id}::{entity_key}"


def _purge_old_windows() -> None:
    """Remove window keys whose all entries have expired (older than 1 hour)."""
    cutoff = time.time() - 3600
    with _temporal_windows_lock:
        stale_keys = [
            k for k, dq in _temporal_windows.items()
            if all(ts < cutoff for ts, _ in dq)
        ]
        for k in stale_keys:
            del _temporal_windows[k]


def record_event_for_temporal(rule_id: str, event_dict: dict[str, Any]) -> None:
    """Append an event snapshot to the temporal window store."""
    global _record_count  # noqa: PLW0603
    entity_key = f"{event_dict.get('hostname', '')}:{event_dict.get('pid', '')}"
    key = _window_key(rule_id, entity_key)
    with _temporal_windows_lock:
        if key not in _temporal_windows:
            _temporal_windows[key] = collections.deque(maxlen=_MAX_WINDOW_ENTRIES)
        _temporal_windows[key].append((time.time(), event_dict))
    _record_count += 1
    if _record_count % 500 == 0:
        _purge_old_windows()


def _count_events_in_window(
    rule_id: str,
    entity_key: str,
    filter_expr: str,
    seconds: int,
) -> int:
    """Count how many events in the rolling window match filter_expr."""
    key = _window_key(rule_id, entity_key)
    with _temporal_windows_lock:
        window = _temporal_windows.get(key)
        snapshot = list(window) if window else []

    if not snapshot:
        return 0

    cutoff = time.time() - seconds
    count = 0
    for ts, snap in snapshot:
        if ts < cutoff:
            continue
        try:
            if _eval_expr(filter_expr, snap, rule_id=""):
                count += 1
        except Exception:  # noqa: BLE001
            pass
    return count


# ---------------------------------------------------------------------------
# Expression evaluator
# ---------------------------------------------------------------------------

_ALLOWED_NODES = {
    ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.UnaryOp, ast.Not,
    ast.Compare, ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.In, ast.NotIn,
    ast.BinOp, ast.Add, ast.Sub,
    ast.Call, ast.Attribute, ast.Subscript,
    ast.Name, ast.Constant, ast.Load,
    ast.List, ast.Tuple,
    ast.IfExp,
}


def _check_ast(node: ast.AST) -> None:
    """Raise ValueError if AST contains disallowed nodes."""
    for child in ast.walk(node):
        if type(child) not in _ALLOWED_NODES:
            raise ValueError(f"Disallowed AST node: {type(child).__name__}")


def _build_namespace(
    event_dict: dict[str, Any],
    rule_id: str,
    entity_key: str,
) -> dict[str, Any]:
    class _Event:
        def __init__(self, d: dict[str, Any]) -> None:
            for k, v in d.items():
                setattr(self, k, v)
        def __getattr__(self, name: str) -> Any:  # noqa: D105
            return None

    def _contains_method(s: Any, sub: str) -> bool:
        return isinstance(s, str) and sub in s

    def _safe_re_match(pattern: str, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        try:
            return bool(re.match(pattern, value))
        except Exception:  # noqa: BLE001
            return False

    def count_events(filter_expr: str, seconds: int) -> int:
        return _count_events_in_window(rule_id, entity_key, filter_expr, seconds)

    return {
        "event": _Event(event_dict),
        "re_match": _safe_re_match,
        "count_events": count_events,
        "contains": _contains_method,
        "True": True,
        "False": False,
        "None": None,
    }


def _eval_expr(
    condition: str,
    event_dict: dict[str, Any],
    rule_id: str,
    entity_key: str = "",
) -> bool:
    # Normalise multiline conditions: join non-empty lines with a space.
    # Lines already carry leading "and"/"or" connectors — no extra keyword needed.
    lines = [ln.strip() for ln in condition.splitlines() if ln.strip()]
    expr = " ".join(lines) if lines else "False"

    # Handle ``contains`` as infix: rewrite `X contains Y` → `contains(X, Y)`
    expr = re.sub(
        r'([^\s"\'(]+(?:\.[^\s"\'(]+)*)\s+contains\s+("[^"]*"|\'[^\']*\')',
        r'contains(\1, \2)',
        expr,
    )

    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Syntax error in condition: {exc}") from exc

    _check_ast(tree)
    code = compile(tree, "<rule_condition>", "eval")
    ns = _build_namespace(event_dict, rule_id, entity_key)
    result = eval(code, {"__builtins__": {}}, ns)  # noqa: S307
    return bool(result)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def evaluate(
    rule: RuleDefinition,
    event: UniversalEvent,
) -> bool:
    """Return True if *event* matches *rule*.

    For temporal rules, also records the event in the sliding window and
    checks the count threshold.
    """
    event_dict = event.model_dump()
    entity_key = f"{event.hostname}:{event.pid}"

    # Platform filter
    if rule.platforms and event_dict.get("os") not in rule.platforms:
        return False

    try:
        matched = _eval_expr(rule.condition, event_dict, rule.id, entity_key)
    except Exception as exc:  # noqa: BLE001
        _log.debug("rule_eval_error", rule_id=rule.id, error=str(exc))
        return False

    if not matched:
        return False

    if rule.timeframe is None:
        return True

    # Temporal rule: record and check threshold
    record_event_for_temporal(rule.id, event_dict)
    count = _count_events_in_window(rule.id, entity_key, rule.condition, rule.timeframe)
    threshold = rule.threshold if rule.threshold is not None else 1
    return count >= threshold
