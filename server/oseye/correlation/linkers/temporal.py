"""TemporalLinker — correlates alerts that occur in rapid succession on a host.

Designed for tight attack chains where different tools fire within seconds:
e.g. a reverse shell spawns, immediately reads /etc/shadow, then connects out.
The SameHostLinker uses a 5-minute window; this linker uses 60 seconds and
rewards close temporal proximity with a higher base score.

Score formula:
    0.0  — different host, outside window, or low severity
    0.55 — same host + within 60s (base)
    0.55–0.85 — + MITRE technique overlap
    0.85–1.0  — + techniques are in a known kill-chain sequence
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oseye.core.schema import Alert, Incident

_KILL_CHAIN_SEQUENCES: list[frozenset[str]] = [
    # Credential access → exfiltration
    frozenset({"T1003", "T1041", "T1048"}),
    # Execution → persistence → privilege escalation
    frozenset({"T1059", "T1053", "T1548"}),
    # Discovery → lateral movement
    frozenset({"T1046", "T1021", "T1570"}),
    # Defense evasion → command and control
    frozenset({"T1070", "T1071", "T1105"}),
]

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_BASE = 0.55
_MITRE_BONUS_MAX = 0.30
_KILLCHAIN_BONUS = 0.15


class TemporalLinker:
    """Links alerts firing within a tight time window on the same host."""

    name = "temporal_proximity"

    def __init__(self, timeframe_seconds: int = 60) -> None:
        self._timeframe = timeframe_seconds

    async def score(self, alert: "Alert", incident: "Incident") -> float:
        if _SEVERITY_ORDER.get(alert.severity, -1) < _SEVERITY_ORDER["medium"]:
            return 0.0

        if alert.hostname != incident.hostname:
            return 0.0

        cutoff = datetime.now(UTC) - timedelta(seconds=self._timeframe)
        if incident.created_at < cutoff:
            return 0.0

        base = _BASE

        alert_techniques = set(alert.mitre_techniques or [])
        incident_tactics = set(incident.mitre_tactics)

        if alert_techniques:
            overlap = len(alert_techniques & incident_tactics) / len(alert_techniques)
            base = min(base + _MITRE_BONUS_MAX * overlap, _BASE + _MITRE_BONUS_MAX)

        # Kill-chain bonus: alert adds a technique that completes a known sequence
        combined = alert_techniques | incident_tactics
        for seq in _KILL_CHAIN_SEQUENCES:
            if len(seq & combined) >= 2 and alert_techniques & seq:
                base = min(1.0, base + _KILLCHAIN_BONUS)
                break

        return base
