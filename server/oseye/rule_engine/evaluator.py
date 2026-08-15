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
# F-05: max TTL used for eager pruning in record_event_for_temporal
_MAX_TTL = 3600  # seconds — entries older than this are always stale
_temporal_windows_lock = threading.Lock()
_record_count = 0  # global call counter for periodic purge


def _window_key(rule_id: str, entity_key: str) -> str:
    return f"{rule_id}::{entity_key}"


def _purge_old_windows() -> None:
    """Remove window keys whose all entries have expired (older than _MAX_TTL)."""
    cutoff = time.time() - _MAX_TTL
    with _temporal_windows_lock:
        stale_keys = [
            k for k, dq in _temporal_windows.items()
            if not dq or all(ts < cutoff for ts, _ in dq)
        ]
        for k in stale_keys:
            del _temporal_windows[k]


def record_event_for_temporal(
    rule_id: str,
    event_dict: dict[str, Any],
    entity_key: str | None = None,
) -> None:
    """Append an event snapshot to the temporal window store."""
    global _record_count  # noqa: PLW0603
    if entity_key is None:
        entity_key = f"{event_dict.get('hostname', '')}:{event_dict.get('pid', '')}"
    key = _window_key(rule_id, entity_key)
    cutoff = time.time() - _MAX_TTL
    # Merged into one lock acquisition — no I/O between the two former blocks.
    with _temporal_windows_lock:
        if key not in _temporal_windows:
            _temporal_windows[key] = collections.deque(maxlen=_MAX_WINDOW_ENTRIES)
        dq = _temporal_windows[key]
        dq.append((time.time(), event_dict))
        # F-05: eagerly prune entries older than max TTL to prevent unbounded growth
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        # F-05: delete the key when the window becomes empty after pruning
        if not dq:
            del _temporal_windows[key]
        # W-10: increment under the same lock (was a separate acquisition before)
        _record_count += 1
        _should_purge = (_record_count % 500 == 0)
    if _should_purge:
        _purge_old_windows()


def _count_events_in_window(
    rule_id: str,
    entity_key: str,
    filter_expr: str,
    seconds: int,
) -> int:
    """Count how many events in the rolling window match filter_expr."""
    key = _window_key(rule_id, entity_key)
    cutoff = time.time() - seconds
    with _temporal_windows_lock:
        window = _temporal_windows.get(key)
        if window is None:
            return 0
        # F-05: eagerly prune entries outside this rule's timeframe
        while window and window[0][0] < cutoff:
            window.popleft()
        # F-05: delete the key if the window is now empty to prevent memory leak
        if not window:
            del _temporal_windows[key]
            return 0
        snapshot = list(window)

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

# F-03 / F-02: detect nested quantifiers and alternation-based ReDoS patterns.
_REDOS_NESTED_RE = re.compile(
    r'(\([^)]*[+*{][^)]*\)\s*[+*{?])'
    r'|(\([^)]*\|[^)]*\)\s*[+*{?])'
)
_MAX_REGEX_LEN = 200

# Precompiled re.sub patterns for condition preprocessing.
_RE_CONTAINS = re.compile(
    r'([^\s"\'(]+(?:\.[^\s"\'(]+)*)\s+contains\s+("[^"]*"|\'[^\']*\')'
)
_RE_STARTS_WITH = re.compile(
    r'([^\s"\'(]+(?:\.[^\s"\'(]+)*)\s+starts_with\s+("[^"]*"|\'[^\']*\')'
)
_RE_ENDS_WITH = re.compile(
    r'([^\s"\'(]+(?:\.[^\s"\'(]+)*)\s+ends_with\s+("[^"]*"|\'[^\']*\')'
)


def _check_ast(node: ast.AST) -> None:
    """Raise ValueError if AST contains disallowed nodes or attribute names."""
    for child in ast.walk(node):
        if type(child) not in _ALLOWED_NODES:
            raise ValueError(f"Disallowed AST node: {type(child).__name__}")
        if isinstance(child, ast.Attribute) and child.attr.startswith("_"):
            raise ValueError(f"Disallowed attribute access: {child.attr!r}")


def _preprocess_expr(condition: str) -> str:
    """Normalise a raw condition string into a valid Python expression."""
    lines = [ln.strip() for ln in condition.splitlines() if ln.strip()]
    expr = " ".join(lines) if lines else "False"
    expr = _RE_CONTAINS.sub(r'contains(\1, \2)', expr)
    expr = _RE_STARTS_WITH.sub(r'\1.startswith(\2)', expr)
    expr = _RE_ENDS_WITH.sub(r'\1.endswith(\2)', expr)
    return expr


def compile_rule_condition(condition_str: str) -> Any:
    """Compile a rule condition to a code object. Call once at rule load time.

    Raises ValueError on syntax errors or disallowed AST nodes.
    """
    try:
        expr = _preprocess_expr(condition_str)
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError as exc:
            raise ValueError(f"Syntax error in condition: {exc}") from exc
        _check_ast(tree)
        return compile(tree, "<rule_condition>", "eval")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Failed to compile condition: {exc}") from exc


# ---------------------------------------------------------------------------
# Sandbox classes — defined at module level so they are NOT recreated per call.
# ---------------------------------------------------------------------------

class _Event:
    """Proxy object that exposes event fields to the sandbox.

    F-02: blocks all _-prefixed attribute access at runtime (defense in depth
    alongside the _check_ast guard), closing the __class__ chain.
    """

    def __init__(self, d: dict[str, Any]) -> None:
        for k, v in d.items():
            if not k.startswith("_"):
                object.__setattr__(self, k, v)

    def __getattribute__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(f"Access denied: {name!r}")
        return object.__getattribute__(self, name)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(f"Access denied: {name!r}")
        return None


class _SafeCallable:
    """Thin callable wrapper — only __call__ is reachable from eval.

    F-01: hides __globals__, __code__, __closure__ from the sandbox.
    """

    __slots__ = ("_fn",)

    def __init__(self, fn: Any) -> None:
        object.__setattr__(self, "_fn", fn)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        fn = object.__getattribute__(self, "_fn")
        return fn(*args, **kwargs)

    def __getattribute__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(f"Access denied: {name!r}")
        return object.__getattribute__(self, name)


def _build_namespace(
    event_dict: dict[str, Any],
    rule_id: str,
    entity_key: str,
) -> dict[str, Any]:
    def _contains_method(s: Any, sub: str) -> bool:
        return isinstance(s, str) and sub in s

    def _safe_re_match(pattern: str, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        if len(pattern) > _MAX_REGEX_LEN:
            return False
        if _REDOS_NESTED_RE.search(pattern):
            return False
        try:
            return bool(re.match(pattern, value))
        except Exception:  # noqa: BLE001
            return False

    def count_events(filter_expr: str, seconds: int) -> int:
        return _count_events_in_window(rule_id, entity_key, filter_expr, seconds)

    return {
        "event": _Event(event_dict),
        "re_match": _SafeCallable(_safe_re_match),
        "count_events": _SafeCallable(count_events),
        "contains": _SafeCallable(_contains_method),
        "True": True,
        "False": False,
        "None": None,
    }


def _eval_expr(
    condition: str,
    event_dict: dict[str, Any],
    rule_id: str,
    entity_key: str = "",
    compiled_code: Any = None,
) -> bool:
    if compiled_code is None:
        # Slow path: compile on the fly (dynamically created rules or fallback).
        expr = _preprocess_expr(condition)
        try:
            tree = ast.parse(expr, mode="eval")
        except SyntaxError as exc:
            raise ValueError(f"Syntax error in condition: {exc}") from exc
        _check_ast(tree)
        compiled_code = compile(tree, "<rule_condition>", "eval")

    ns = _build_namespace(event_dict, rule_id, entity_key)
    result = eval(compiled_code, {"__builtins__": {}}, ns)  # noqa: S307
    return bool(result)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def evaluate(
    rule: RuleDefinition,
    event: UniversalEvent | None = None,
    entity_key: str | None = None,
    event_dict: dict[str, Any] | None = None,
) -> bool:
    """Return True if *event* matches *rule*.

    Parameters
    ----------
    event:
        The UniversalEvent to evaluate. Either ``event`` or ``event_dict``
        must be provided.
    event_dict:
        Pre-computed ``event.model_dump()`` dict.  When provided by the
        RuleEngine (which calls model_dump once for all rules), this avoids
        redundant Pydantic serialisation.
    entity_key:
        Stable key for temporal window bucketing.
    """
    if event_dict is None:
        if event is None:
            raise ValueError("Either event or event_dict must be provided")
        event_dict = event.model_dump()

    if entity_key is None:
        if event is not None:
            entity_key = f"{event.hostname}:{event.pid}"
        else:
            entity_key = (
                f"{event_dict.get('hostname', '')}:{event_dict.get('pid', '')}"
            )

    # Platform filter
    if rule.platforms and event_dict.get("os") not in rule.platforms:
        return False

    try:
        matched = _eval_expr(
            rule.condition,
            event_dict,
            rule.id,
            entity_key,
            compiled_code=rule.compiled_code,
        )
    except Exception as exc:  # noqa: BLE001
        _log.debug("rule_eval_error", rule_id=rule.id, error=str(exc))
        return False

    if not matched:
        return False

    if rule.timeframe is None:
        return True

    # Temporal rule: record and check threshold.
    record_event_for_temporal(rule.id, event_dict, entity_key=entity_key)
    count = _count_events_in_window(rule.id, entity_key, rule.condition, rule.timeframe)
    threshold = rule.threshold if rule.threshold is not None else 1
    return count >= threshold
