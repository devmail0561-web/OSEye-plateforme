"""P7.06b — Self-contained HTML report for forensic cases."""

from __future__ import annotations

import html
from datetime import UTC, datetime

from oseye.core.schema import Alert, ForensicCase, UniversalEvent

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#6b7280",
}

_STATUS_MAP: dict[str, str] = {
    "open": "Open",
    "in_progress": "In Progress",
    "resolved": "Resolved",
    "archived": "Archived",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: #0f1117; color: #e2e8f0;
  font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px;
  padding: 32px;
}
h1 { font-size: 22px; font-weight: 700; color: #f1f5f9; }
h2 { font-size: 16px; font-weight: 600; color: #94a3b8; margin: 28px 0 12px; }
.header { background: #161b27; border-radius: 10px; padding: 24px 28px; margin-bottom: 24px; }
.meta { color: #64748b; font-size: 12px; margin-top: 6px; }
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 4px;
  font-size: 12px; font-weight: 700; text-transform: uppercase;
  margin-left: 10px; vertical-align: middle;
}
.tiles { display: flex; gap: 16px; margin-bottom: 24px; }
.tile {
  flex: 1; background: #161b27; border-radius: 10px; padding: 20px;
  text-align: center;
}
.tile .val { font-size: 32px; font-weight: 700; color: #4f8ef7; }
.tile .lbl { font-size: 12px; color: #64748b; margin-top: 4px; }
table {
  width: 100%; border-collapse: collapse;
  background: #161b27; border-radius: 10px; overflow: hidden;
}
th {
  background: #1e2536; color: #94a3b8; font-size: 12px;
  text-align: left; padding: 10px 14px; font-weight: 600;
}
td { padding: 9px 14px; border-top: 1px solid #1e2536; color: #cbd5e1; }
tr:hover td { background: #1a2032; }
.sev { font-weight: 600; font-size: 12px; }
.tag {
  display: inline-block; padding: 2px 8px; border-radius: 3px;
  background: #1e2940; color: #4f8ef7; font-size: 11px; margin: 1px;
}
"""


def _badge(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "#6b7280")
    return f'<span class="badge" style="background:{color};">{html.escape(severity.upper())}</span>'


def _sev_cell(severity: str) -> str:
    color = _SEVERITY_COLORS.get(severity, "#6b7280")
    return f'<span class="sev" style="color:{color};">{html.escape(severity.upper())}</span>'


def _iso(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat(timespec="seconds")


def _ns_to_iso(ns: int) -> str:
    try:
        return datetime.fromtimestamp(ns / 1e9, tz=UTC).isoformat(timespec="seconds")
    except (OSError, OverflowError):
        return str(ns)


def _timeline_rows(timeline: list[dict]) -> str:
    if not timeline:
        return "<tr><td colspan='4' style='color:#4a5568;text-align:center;'>No entries</td></tr>"
    rows = []
    for entry in sorted(timeline, key=lambda e: e.get("ts", 0)):
        ts = html.escape(_ns_to_iso(entry.get("ts", 0)))
        sev = str(entry.get("severity", "info"))
        title = html.escape(str(entry.get("title", "—")))
        host = html.escape(str(entry.get("hostname", "") or "—"))
        rows.append(
            f"<tr><td>{ts}</td><td>{_sev_cell(sev)}</td>"
            f"<td>{title}</td><td>{host}</td></tr>"
        )
    return "\n".join(rows)


def _custody_rows(case: ForensicCase) -> str:
    if not case.custody_log:
        return "<tr><td colspan='4' style='color:#4a5568;text-align:center;'>No entries</td></tr>"
    rows = []
    for entry in case.custody_log:
        rows.append(
            f"<tr><td>{html.escape(_iso(entry.timestamp))}</td>"
            f"<td>{html.escape(entry.operator)}</td>"
            f"<td>{html.escape(entry.action)}</td>"
            f"<td>{html.escape(entry.detail)}</td></tr>"
        )
    return "\n".join(rows)


def _evidence_rows(case: ForensicCase) -> str:
    if not case.evidence:
        return "<tr><td colspan='4' style='color:#4a5568;text-align:center;'>No items</td></tr>"
    rows = []
    for ev in case.evidence:
        desc = html.escape(ev.description or "")
        rows.append(
            f"<tr><td>{html.escape(str(ev.evidence_id))}</td>"
            f"<td>{html.escape(ev.type)}</td>"
            f"<td>{html.escape(ev.added_by)}</td>"
            f"<td>{desc}</td></tr>"
        )
    return "\n".join(rows)


def export_html(
    case: ForensicCase,
    events: list[UniversalEvent],
    alerts: list[Alert],
    timeline: list[dict],
) -> str:
    """Return a self-contained HTML string report."""
    tags_html = "".join(f'<span class="tag">{html.escape(t)}</span>' for t in case.tags)

    body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSEye — {html.escape(case.title)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="header">
  <h1>{html.escape(case.title)}{_badge(case.severity)}</h1>
  <p class="meta">
    Case ID: {html.escape(str(case.case_id))} &nbsp;·&nbsp;
    Status: {html.escape(_STATUS_MAP.get(case.status, case.status))} &nbsp;·&nbsp;
    Created: {html.escape(_iso(case.created_at))} &nbsp;·&nbsp;
    Updated: {html.escape(_iso(case.updated_at))}
  </p>
  <p class="meta" style="margin-top:8px;">{html.escape(case.description)}</p>
  <p class="meta" style="margin-top:8px;">{tags_html}</p>
</div>

<div class="tiles">
  <div class="tile"><div class="val">{len(events)}</div><div class="lbl">Events</div></div>
  <div class="tile"><div class="val">{len(alerts)}</div><div class="lbl">Alerts</div></div>
  <div class="tile"><div class="val">{len(case.evidence)}</div><div class="lbl">Evidence</div></div>
  <div class="tile"><div class="val">{len(case.custody_log)}</div>
    <div class="lbl">Custody entries</div></div>
</div>

<h2>Timeline</h2>
<table>
  <thead>
    <tr><th>Timestamp</th><th>Severity</th><th>Title</th><th>Host</th></tr>
  </thead>
  <tbody>
    {_timeline_rows(timeline)}
  </tbody>
</table>

<h2>Custody Log</h2>
<table>
  <thead>
    <tr><th>Timestamp</th><th>Operator</th><th>Action</th><th>Detail</th></tr>
  </thead>
  <tbody>
    {_custody_rows(case)}
  </tbody>
</table>

<h2>Evidence</h2>
<table>
  <thead>
    <tr><th>ID</th><th>Type</th><th>Added by</th><th>Description</th></tr>
  </thead>
  <tbody>
    {_evidence_rows(case)}
  </tbody>
</table>

</body>
</html>"""
    return body
