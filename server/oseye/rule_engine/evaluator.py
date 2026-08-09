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
# Matches: (a+)+, (a*)*, (a+)*, (a|b+)+, (x{2,})+, (a|aa)+, (\w|\d)+, etc.
_REDOS_NESTED_RE = re.compile(
    r'(\([^)]*[+*{][^)]*\)\s*[+*{?])'  # quantifier inside group before outer quantifier
    r'|(\([^)]*\|[^)]*\)\s*[+*{?])'    # alternation group before outer quantifier
)
_MAX_REGEX_LEN = 200


def _check_ast(node: ast.AST) -> None:
    """Raise ValueError if AST contains disallowed nodes or attribute names.

    F1/F-02: Block any attribute access whose name starts with ``_`` to
    prevent dunder-chain sandbox escapes such as
    ``"".__class__.__mro__[-1].__subclasses__()``.
    """
    for child in ast.walk(node):
        if type(child) not in _ALLOWED_NODES:
            raise ValueError(f"Disallowed AST node: {type(child).__name__}")
        # F1/F-02: reject private and dunder attribute names at AST level
        if isinstance(child, ast.Attribute) and child.attr.startswith("_"):
            raise ValueError(f"Disallowed attribute access: {child.attr!r}")


def _build_namespace(
    event_dict: dict[str, Any],
    rule_id: str,
    entity_key: str,
) -> dict[str, Any]:
    # F-02: _Event blocks all _-prefixed attribute access at runtime (defense
    # in depth alongside the _check_ast guard), closing the __class__ chain.
    class _Event:
        def __init__(self, d: dict[str, Any]) -> None:
            for k, v in d.items():
                # Skip keys that start with '_' to avoid leaking internal state
                if not k.startswith("_"):
                    object.__setattr__(self, k, v)

        def __getattribute__(self, name: str) -> Any:  # noqa: D105
            if name.startswith("_"):
                raise AttributeError(f"Access denied: {name!r}")
            return object.__getattribute__(self, name)

        def __getattr__(self, name: str) -> Any:  # noqa: D105
            # __getattr__ is called only when __getattribute__ raises AttributeError.
            # Re-block private names so the fallback also refuses them.
            if name.startswith("_"):
                raise AttributeError(f"Access denied: {name!r}")
            return None

    # F-01: wrap each callable in a class instance that exposes only __call__,
    # preventing access to __globals__, __code__, __closure__, etc.
    class _SafeCallable:
        """Thin callable wrapper — only __call__ is reachable from eval."""

        __slots__ = ("_fn",)

        def __init__(self, fn: Any) -> None:
            object.__setattr__(self, "_fn", fn)

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            # Retrieve via object.__getattribute__ to bypass our own override
            fn = object.__getattribute__(self, "_fn")
            return fn(*args, **kwargs)

        def __getattribute__(self, name: str) -> Any:
            # Python resolves __call__ through type(obj).__call__, not through
            # instance attribute lookup, so blocking all _-prefixed names here
            # does not break callability.
            if name.startswith("_"):
                raise AttributeError(f"Access denied: {name!r}")
            return object.__getattribute__(self, name)

    def _contains_method(s: Any, sub: str) -> bool:
        return isinstance(s, str) and sub in s

    def _safe_re_match(pattern: str, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        # F-03: ReDoS guard — reject long patterns and nested quantifiers
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
        # F-01: all callables are wrapped in _SafeCallable to hide __globals__
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
    # Handle ``starts_with`` as infix: rewrite `X starts_with Y` → `X.startswith(Y)`
    expr = re.sub(
        r'([^\s"\'(]+(?:\.[^\s"\'(]+)*)\s+starts_with\s+("[^"]*"|\'[^\']*\')',
        r'\1.startswith(\2)',
        expr,
    )
    # Handle ``ends_with`` as infix: rewrite `X ends_with Y` → `X.endswith(Y)`
    expr = re.sub(
        r'([^\s"\'(]+(?:\.[^\s"\'(]+)*)\s+ends_with\s+("[^"]*"|\'[^\']*\')',
        r'\1.endswith(\2)',
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
    entity_key: str | None = None,
) -> bool:
    """Return True if *event* matches *rule*.

    For temporal rules, also records the event in the sliding window and
    checks the count threshold.

    Parameters
    ----------
    entity_key:
        Stable key for temporal window bucketing.  When provided by the
        RuleEngine (which applies the PID reuse guard), that value is used.
        Falls back to hostname:pid for callers that omit it.
    """
    event_dict = event.model_dump()
    if entity_key is None:
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

    # Temporal rule: record and check threshold — pass the stable entity_key so
    # the window bucket matches what _count_events_in_window will query.
    record_event_for_temporal(rule.id, event_dict, entity_key=entity_key)
    count = _count_events_in_window(rule.id, entity_key, rule.condition, rule.timeframe)
    threshold = rule.threshold if rule.threshold is not None else 1
    return count >= threshold
