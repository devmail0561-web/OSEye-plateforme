"""YAML rule parser — loads rules from builtin/ and custom/ directories."""

from __future__ import annotations

from pathlib import Path

import yaml

from oseye.core.observability import get_logger
from oseye.rule_engine.models import RuleDefinition

_log = get_logger(__name__)

_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_VALID_RULE_TYPES = {"anomaly", "surveillance"}


def _parse_rule(data: dict[str, object], source: str) -> RuleDefinition | None:
    """Parse a single rule dict.  Returns None and logs on validation error."""
    try:
        rule_id = str(data["id"])
        name = str(data.get("name", rule_id))
        enabled = bool(data.get("enabled", True))
        severity = str(data.get("severity", "medium"))
        if severity not in _VALID_SEVERITIES:
            _log.warning("rule_invalid_severity", rule_id=rule_id, severity=severity)
            return None
        condition = str(data.get("condition", "")).strip()
        if not condition:
            _log.warning("rule_empty_condition", rule_id=rule_id)
            return None
        timeframe_raw = data.get("timeframe")
        timeframe = int(str(timeframe_raw)) if timeframe_raw is not None else None
        threshold_raw = data.get("threshold")
        threshold = int(str(threshold_raw)) if threshold_raw is not None else None
        actions_raw = data.get("actions", ["ALERT"])
        if not isinstance(actions_raw, list):
            _log.warning("rule_actions_not_list", rule_id=rule_id, actions=actions_raw)
            actions_raw = [str(actions_raw)]
        actions: list[str] = [str(a) for a in actions_raw]
        tags_raw = data.get("tags", [])
        tags: list[str] = [str(t) for t in (tags_raw if isinstance(tags_raw, list) else [])]
        mitre_raw = data.get("mitre", [])
        mitre: list[str] = [str(m) for m in (mitre_raw if isinstance(mitre_raw, list) else [])]
        platforms_raw = data.get("platforms", [])
        platforms: list[str] = [
            str(p) for p in (platforms_raw if isinstance(platforms_raw, list) else [])
        ]
        categories_raw = data.get("categories", [])
        categories: list[str] = [
            str(c) for c in (categories_raw if isinstance(categories_raw, list) else [])
        ]
        explanation = str(data.get("explanation", ""))
        entity_key_raw = data.get("entity_key")
        entity_key = str(entity_key_raw) if entity_key_raw else None
        rule_type_raw = str(data.get("rule_type", "anomaly"))
        if rule_type_raw not in _VALID_RULE_TYPES:
            _log.warning("rule_invalid_rule_type", rule_id=rule_id, rule_type=rule_type_raw)
            rule_type_raw = "anomaly"
        if timeframe is not None and timeframe <= 0:
            _log.warning("rule_invalid_timeframe", rule_id=rule_id, timeframe=timeframe)
            return None
        if threshold is not None and threshold < 1:
            _log.warning("rule_invalid_threshold", rule_id=rule_id, threshold=threshold)
            return None

        return RuleDefinition(
            id=rule_id,
            name=name,
            enabled=enabled,
            severity=severity,
            condition=condition,
            timeframe=timeframe,
            threshold=threshold,
            actions=actions,
            tags=tags,
            mitre=mitre,
            platforms=platforms,
            categories=categories,
            explanation=explanation,
            source=source,
            entity_key=entity_key,
            rule_type=rule_type_raw,  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as exc:
        _log.warning("rule_parse_error", error=str(exc))
        return None


def load_rules_from_file(path: Path, source: str) -> list[RuleDefinition]:
    """Load all rules from a single YAML file."""
    try:
        content = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(content)
    except Exception as exc:  # noqa: BLE001
        _log.error("rule_file_load_error", path=str(path), error=str(exc))
        return []

    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        _log.warning("rule_file_unexpected_format", path=str(path))
        return []

    rules: list[RuleDefinition] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        rule = _parse_rule({str(k): v for k, v in item.items()}, source)
        if rule is not None:
            rules.append(rule)
    return rules


def load_rules_from_dir(directory: Path, source: str) -> list[RuleDefinition]:
    """Recursively load all .yaml / .yml rules from a directory."""
    if not directory.exists():
        return []
    rules: list[RuleDefinition] = []
    for path in sorted(directory.rglob("*.yaml")) + sorted(directory.rglob("*.yml")):
        rules.extend(load_rules_from_file(path, source))
    return rules


def load_all_rules(rules_root: Path) -> list[RuleDefinition]:
    """Load builtin + custom rules.  Custom rules override builtin on same id."""
    builtin = load_rules_from_dir(rules_root / "builtin", "builtin")
    custom = load_rules_from_dir(rules_root / "custom", "custom")

    by_id: dict[str, RuleDefinition] = {}
    for rule in builtin:
        by_id[rule.id] = rule
    for rule in custom:
        by_id[rule.id] = rule  # custom overrides builtin with same id

    loaded = list(by_id.values())
    _log.info("rules_loaded", total=len(loaded), builtin=len(builtin), custom=len(custom))
    return loaded
