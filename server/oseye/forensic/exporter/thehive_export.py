"""P7.08 — TheHive 5 case export for forensic cases."""

from __future__ import annotations

import ipaddress as _ipaddress

from oseye.core.schema import Alert, ForensicCase

_SEVERITY_MAP: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_STATUS_MAP: dict[str, str] = {
    "open": "New",
    "in_progress": "InProgress",
    "resolved": "Resolved",
    "archived": "Archived",
}


def _is_valid_ip(addr: str) -> bool:
    try:
        _ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def _collect_distinct_ips(alerts: list[Alert]) -> list[str]:
    seen: set[str] = set()
    ips: list[str] = []
    for alert in alerts:
        entity = alert.entity_id
        # entity_id may be "hostname:pid" or a bare IP
        candidate = entity.split(":")[0] if ":" in entity else entity
        if _is_valid_ip(candidate) and candidate not in seen:
            seen.add(candidate)
            ips.append(candidate)
    return ips


def export_thehive_case(case: ForensicCase, alerts: list[Alert]) -> dict:
    """Return a TheHive 5 case payload ready for POST /api/v1/case."""
    observables: list[dict] = [
        {"dataType": "ip", "data": ip, "tags": ["network"]}
        for ip in _collect_distinct_ips(alerts)
    ]

    return {
        "title": case.title,
        "description": case.description or f"OSEye forensic case — {case.case_id}",
        "severity": _SEVERITY_MAP.get(case.severity, 2),
        "status": _STATUS_MAP.get(case.status, "New"),
        "tags": ["osEye", *case.tags],
        "tasks": [],
        "observables": observables,
    }
