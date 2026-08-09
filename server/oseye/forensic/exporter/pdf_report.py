"""P7.06c — PDF export via WeasyPrint (graceful degradation if not installed)."""

from __future__ import annotations

from oseye.core.schema import Alert, ForensicCase, UniversalEvent
from oseye.forensic.exporter.html_report import export_html


def export_pdf(
    case: ForensicCase,
    events: list[UniversalEvent],
    alerts: list[Alert],
    timeline: list[dict],
) -> bytes:
    """Return a PDF bytes object via WeasyPrint from the HTML report.

    Raises ImportError with a descriptive message if WeasyPrint is not installed.
    """
    try:
        import weasyprint  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "WeasyPrint is required for PDF export. "
            "Install it with: pip install weasyprint"
        ) from exc

    report_html = export_html(case, events, alerts, timeline)
    return weasyprint.HTML(string=report_html).write_pdf()  # type: ignore[no-any-return]
