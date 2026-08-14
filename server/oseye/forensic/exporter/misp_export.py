"""P7.07 — MISP v2.4 event export for forensic cases."""

from __future__ import annotations

import ipaddress

from oseye.core.schema import Alert, ForensicCase

_SEVERITY_THREAT_LEVEL: dict[str, str] = {
    "critical": "1",
    "high": "2",
    "medium": "3",
    "low": "4",
}

def _is_valid_ip(val: str) -> bool:
    """F-08: use ipaddress.ip_address() instead of a regex that accepts invalid octets."""
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False


def _collect_ips(alerts: list[Alert]) -> list[str]:
    seen: set[str] = set()
    ips: list[str] = []
    for alert in alerts:
        entity = alert.entity_id
        candidate = entity.split(":")[0] if ":" in entity else entity
        if _is_valid_ip(candidate) and candidate not in seen:
            seen.add(candidate)
            ips.append(candidate)
    return ips


def _collect_techniques(alerts: list[Alert]) -> list[str]:
    seen: set[str] = set()
    techniques: list[str] = []
    for alert in alerts:
        for t in alert.mitre_techniques:
            if t not in seen:
                seen.add(t)
                techniques.append(t)
    return techniques


def export_misp_event(case: ForensicCase, alerts: list[Alert]) -> dict:
    """Return a MISP event dict ready for POST /events on a MISP instance."""
    threat_level = _SEVERITY_THREAT_LEVEL.get(case.severity, "3")

    attributes: list[dict] = []

    for ip in _collect_ips(alerts):
        attributes.append({
            "type": "ip-dst",
            "category": "Network activity",
            "value": ip,
            "to_ids": True,
            "comment": "Observed in OSEye alert",
        })

    for technique in _collect_techniques(alerts):
        attributes.append({
            "type": "text",
            "category": "External analysis",
            "value": technique,
            "to_ids": False,
            "comment": "MITRE ATT&CK technique",
        })

    return {
        "Event": {
            "info": case.title,
            "date": case.created_at.date().isoformat(),
            "threat_level_id": threat_level,
            "analysis": "2",
            "distribution": "0",
            "Attribute": attributes,
            "Tag": [{"name": "osEye"}, {"name": "tlp:amber"}],
        }
    }
