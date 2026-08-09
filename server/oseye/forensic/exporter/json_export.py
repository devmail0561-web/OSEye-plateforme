"""P7.06a — JSON export for forensic case bundles."""

from __future__ import annotations

import json

from oseye.core.schema import Alert, ForensicCase, UniversalEvent


def export_json(
    case: ForensicCase,
    events: list[UniversalEvent],
    alerts: list[Alert],
) -> str:
    """Return a JSON string with the full case bundle (pretty-printed)."""
    bundle = {
        "case": case.model_dump(mode="json"),
        "events": [e.model_dump(mode="json") for e in events],
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "evidence": [ev.model_dump(mode="json") for ev in case.evidence],
        "custody_log": [c.model_dump(mode="json") for c in case.custody_log],
        "notes": [n.model_dump(mode="json") for n in case.notes],
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False)
