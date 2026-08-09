"""Internal models for the Rule Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class RuleDefinition:
    """Parsed representation of a YAML rule."""

    id: str
    name: str
    enabled: bool
    severity: str  # info | low | medium | high | critical
    condition: str  # raw expression string
    timeframe: int | None  # seconds, None = single-event rule
    threshold: int | None  # min count for temporal rules
    actions: list[str]
    tags: list[str]
    mitre: list[str]
    platforms: list[str]  # empty = all platforms
    categories: list[str]  # empty = all categories (used for index-based fast dispatch)
    explanation: str
    source: str  # builtin | custom


@dataclass(slots=True)
class RuleMatch:
    """Result of a successful rule evaluation."""

    rule_id: str
    rule_name: str
    severity: str
    actions: list[str]
    tags: list[str]
    mitre: list[str]
    explanation: str
    matched_fields: dict[str, Any] = field(default_factory=dict)
