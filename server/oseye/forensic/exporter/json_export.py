"""P7.06a — JSON export for forensic case bundles."""

from __future__ import annotations

import json
import re
from typing import Any

from oseye.core.schema import Alert, ForensicCase, UniversalEvent

# F-05: extended pattern to cover bearer tokens, JWT, passphrase, auth_key, etc.
_SENSITIVE_RE = re.compile(
    r"(password|passwd|secret|token|key|bearer|jwt|passphrase|auth_key|api_key|credential)",
    re.IGNORECASE,
)


def _redact_value(value: str) -> str:
    return "***REDACTED***"


_EVIDENCE_SIZE_CAP = 1_000_000  # 1 MB


def _cap_evidence(ev_dict: dict) -> dict:
    """F-07: truncate evidence content if it exceeds 1 MB."""
    content = ev_dict.get("content")
    if content is not None and len(str(content)) > _EVIDENCE_SIZE_CAP:
        ev_dict = dict(ev_dict)
        ev_dict["content"] = str(content)[:_EVIDENCE_SIZE_CAP] + "...[truncated]"
    return ev_dict


def _redact_dict(d: dict[str, Any]) -> dict[str, Any]:
    """Recursively mask values whose keys match sensitive patterns."""
    result = {}
    for k, v in d.items():
        if _SENSITIVE_RE.search(k):
            result[k] = _redact_value(str(v))
        elif isinstance(v, dict):
            result[k] = _redact_dict(v)
        elif isinstance(v, list):
            result[k] = [_redact_dict(item) if isinstance(item, dict) else item for item in v]
        else:
            result[k] = v
    return result


def export_json(
    case: ForensicCase,
    events: list[UniversalEvent],
    alerts: list[Alert],
    *,
    redact: bool = True,
) -> str:
    """Return a JSON string with the full case bundle (pretty-printed).

    When *redact* is True (default), fields whose keys match sensitive patterns
    (password, secret, token, etc.) are masked in the output.
    """
    bundle = {
        "case": case.model_dump(mode="json"),
        "events": [e.model_dump(mode="json") for e in events],
        "alerts": [a.model_dump(mode="json") for a in alerts],
        "evidence": [_cap_evidence(ev.model_dump(mode="json")) for ev in case.evidence],
        "custody_log": [c.model_dump(mode="json") for c in case.custody_log],
        "notes": [n.model_dump(mode="json") for n in case.notes],
    }
    if redact:
        bundle = _redact_dict(bundle)
    return json.dumps(bundle, indent=2, ensure_ascii=False)
