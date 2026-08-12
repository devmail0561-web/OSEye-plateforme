"""Forensic timeline builder — merges events, alerts and custody entries by timestamp."""

from __future__ import annotations

from oseye.core.schema import Alert, ForensicCase, UniversalEvent

_NS_PER_S = 1_000_000_000


def build_timeline(
    case: ForensicCase,
    events: list[UniversalEvent],
    alerts: list[Alert],
) -> list[dict]:
    """Return a list of heterogeneous entries sorted by timestamp (ascending).

    Each entry has: ts (int, nanoseconds), type, severity, title, detail, id.
    """
    entries: list[dict] = []

    for ev in events:
        entries.append(
            {
                "ts": ev.timestamp_ns,
                "type": "event",
                "severity": ev.severity,
                "title": f"{ev.category}/{ev.type}",
                "detail": ev.resource or ev.cmdline,
                "hostname": ev.hostname,
                "id": str(ev.event_id),
            }
        )

    for alert in alerts:
        ts_ns = int(alert.created_at.timestamp() * _NS_PER_S)
        entries.append(
            {
                "ts": ts_ns,
                "type": "alert",
                "severity": alert.severity,
                "title": alert.title,
                "detail": alert.description,
                "hostname": alert.hostname,
                "id": str(alert.alert_id),
            }
        )

    for entry in case.custody_log:
        ts_ns = int(entry.timestamp.timestamp() * _NS_PER_S)
        entries.append(
            {
                "ts": ts_ns,
                "type": "custody",
                "severity": "info",
                "title": entry.action,
                "detail": entry.detail,
                "hostname": "",
                "id": entry.hash,
            }
        )

    entries.sort(key=lambda e: e["ts"])
    return entries
