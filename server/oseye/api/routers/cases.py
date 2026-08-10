"""Cases router — /api/v1/cases.

Endpoints:
    GET    /api/v1/cases                          — list cases (paginated)
    POST   /api/v1/cases                          — create case
    GET    /api/v1/cases/{id}                     — get case
    PATCH  /api/v1/cases/{id}                     — update case fields
    POST   /api/v1/cases/{id}/notes               — add note
    POST   /api/v1/cases/{id}/evidence            — add evidence item
    POST   /api/v1/cases/{id}/close               — close case
    GET    /api/v1/cases/{id}/timeline            — chronological timeline
    GET    /api/v1/cases/{id}/custody             — custody log
    GET    /api/v1/cases/{id}/export/json         — JSON export
    GET    /api/v1/cases/{id}/export/html         — HTML report
    GET    /api/v1/cases/{id}/export/pdf          — PDF report
    GET    /api/v1/cases/{id}/export/misp         — MISP event payload
    GET    /api/v1/cases/{id}/export/thehive      — TheHive case payload
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, StringConstraints
from slowapi import Limiter
from slowapi.util import get_remote_address

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger
from oseye.core.pagination import PageResult
from oseye.core.schema import CaseNote, EvidenceItem, ForensicCase
from oseye.storage.interface import Pagination

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/cases", tags=["cases"])

_require_reader = require_role("analyst", "admin")
_require_analyst = require_role("analyst", "admin")
_require_admin = require_role("admin")

# SEC-RATELIMIT-001: exports are expensive (full case load + render).
_limiter = Limiter(key_func=get_remote_address)


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------

def _get_case_manager(request: Request) -> Any:
    mgr = getattr(request.app.state, "case_manager", None)
    if mgr is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Case manager not initialised",
        )
    return mgr


def _get_event_repo(request: Request) -> Any:
    return getattr(request.app.state, "event_repo", None)


def _get_alert_repo(request: Request) -> Any:
    return getattr(request.app.state, "alert_repo", None)


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------

class _CreateCaseBody(BaseModel):
    # SEC-CASES-001: length constraints to prevent DoS via oversized payloads
    title: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    severity: str
    description: Annotated[str, StringConstraints(max_length=10_000)] = ""
    tags: list[str] = Field(default_factory=list, max_length=50)
    alert_ids: list[UUID] = Field(default_factory=list, max_length=500)
    event_ids: list[UUID] = Field(default_factory=list, max_length=500)


class _UpdateCaseBody(BaseModel):
    # SEC-CASES-001: length constraints mirror _CreateCaseBody
    title: Annotated[str, StringConstraints(min_length=1, max_length=500)] | None = None
    description: Annotated[str, StringConstraints(max_length=10_000)] | None = None
    severity: str | None = None
    status: str | None = None
    assigned_to: str | None = None
    tags: list[str] | None = Field(default=None, max_length=50)


class _AddNoteBody(BaseModel):
    # SEC-CASES-001: cap note content at 50 000 chars
    content: Annotated[str, StringConstraints(min_length=1, max_length=50_000)]


class _AddEvidenceBody(BaseModel):
    type: str
    # SEC-CASES-001: cap evidence content at 1 MB (characters)
    content: Annotated[str, StringConstraints(min_length=1, max_length=1_000_000)]
    description: str | None = None


class _CloseBody(BaseModel):
    resolution: Annotated[str, StringConstraints(max_length=10_000)] = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("")
async def list_cases(
    request: Request,
    status_filter: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 20,
    _: dict[str, Any] = Depends(_require_reader),
) -> PageResult[ForensicCase]:
    if page < 1:
        raise HTTPException(status_code=422, detail="page must be >= 1")
    if not 1 <= page_size <= 200:
        raise HTTPException(status_code=422, detail="page_size must be between 1 and 200")

    mgr = _get_case_manager(request)
    filters: dict[str, object] = {}
    if status_filter:
        filters["status"] = status_filter
    if severity:
        filters["severity"] = severity

    pagination = Pagination(limit=page_size, offset=(page - 1) * page_size)
    return await mgr.list_cases(filters, pagination)  # type: ignore[no-any-return]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_case(
    request: Request,
    body: _CreateCaseBody,
    token: dict[str, Any] = Depends(_require_analyst),
) -> ForensicCase:
    operator: str = token.get("sub", "unknown")
    mgr = _get_case_manager(request)
    return await mgr.create_case(  # type: ignore[no-any-return]
        title=body.title,
        severity=body.severity,
        created_by=operator,
        description=body.description,
        tags=body.tags,
        alert_ids=body.alert_ids,
        event_ids=body.event_ids,
    )


@router.get("/{case_id}")
async def get_case(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> ForensicCase:
    mgr = _get_case_manager(request)
    case = await mgr.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.patch("/{case_id}")
async def update_case(
    case_id: UUID,
    request: Request,
    body: _UpdateCaseBody,
    token: dict[str, Any] = Depends(_require_analyst),
) -> ForensicCase:
    operator: str = token.get("sub", "unknown")
    mgr = _get_case_manager(request)
    fields = body.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(status_code=422, detail="No fields to update")
    return await mgr.update_case(case_id, operator, **fields)  # type: ignore[no-any-return]


@router.post("/{case_id}/notes", status_code=status.HTTP_201_CREATED)
async def add_note(
    case_id: UUID,
    request: Request,
    body: _AddNoteBody,
    token: dict[str, Any] = Depends(_require_analyst),
) -> CaseNote:
    operator: str = token.get("sub", "unknown")
    mgr = _get_case_manager(request)
    return await mgr.add_note(case_id, author=operator, content=body.content)  # type: ignore[no-any-return]


@router.post("/{case_id}/evidence", status_code=status.HTTP_201_CREATED)
async def add_evidence(
    case_id: UUID,
    request: Request,
    body: _AddEvidenceBody,
    token: dict[str, Any] = Depends(_require_analyst),
) -> EvidenceItem:
    operator: str = token.get("sub", "unknown")
    mgr = _get_case_manager(request)
    return await mgr.add_evidence(  # type: ignore[no-any-return]
        case_id,
        operator=operator,
        type_=body.type,
        content=body.content,
        description=body.description,
    )


@router.post("/{case_id}/close")
async def close_case(
    case_id: UUID,
    request: Request,
    body: _CloseBody = Body(default_factory=_CloseBody),
    token: dict[str, Any] = Depends(_require_analyst),
) -> ForensicCase:
    operator: str = token.get("sub", "unknown")
    mgr = _get_case_manager(request)
    return await mgr.close_case(case_id, operator=operator, resolution=body.resolution)  # type: ignore[no-any-return]


@router.get("/{case_id}/timeline")
async def get_timeline(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> list[dict[str, Any]]:
    from oseye.forensic.timeline import build_timeline

    mgr = _get_case_manager(request)
    case = await mgr.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    event_repo = _get_event_repo(request)
    alert_repo = _get_alert_repo(request)

    events = []
    alerts = []
    if event_repo is not None:
        for eid in case.event_ids:
            ev = await event_repo.get(eid)
            if ev:
                events.append(ev)
    if alert_repo is not None:
        for aid in case.alert_ids:
            al = await alert_repo.get(aid)
            if al:
                alerts.append(al)

    return build_timeline(case, events, alerts)


@router.get("/{case_id}/custody")
async def get_custody(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> list[dict[str, Any]]:
    mgr = _get_case_manager(request)
    case = await mgr.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return [e.model_dump(mode="json") for e in case.custody_log]


# ---------------------------------------------------------------------------
# Export endpoints
# ---------------------------------------------------------------------------

async def _load_case_bundle(
    case_id: UUID, request: Request
) -> tuple[ForensicCase, list[Any], list[Any]]:
    mgr = _get_case_manager(request)
    case = await mgr.get_case(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")

    event_repo = _get_event_repo(request)
    alert_repo = _get_alert_repo(request)

    events = []
    alerts = []
    if event_repo is not None:
        for eid in case.event_ids:
            ev = await event_repo.get(eid)
            if ev:
                events.append(ev)
    if alert_repo is not None:
        for aid in case.alert_ids:
            al = await alert_repo.get(aid)
            if al:
                alerts.append(al)

    return case, events, alerts


@router.get("/{case_id}/export/json")
@_limiter.limit("20/minute")
async def export_json(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> Response:
    from oseye.forensic.exporter.json_export import export_json as _export_json

    case, events, alerts = await _load_case_bundle(case_id, request)
    content = _export_json(case, events, alerts)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="case_{case_id}.json"'},
    )


@router.get("/{case_id}/export/html")
@_limiter.limit("10/minute")
async def export_html(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> Response:
    from oseye.forensic.exporter.html_report import export_html as _export_html
    from oseye.forensic.timeline import build_timeline

    case, events, alerts = await _load_case_bundle(case_id, request)
    timeline = build_timeline(case, events, alerts)
    content = _export_html(case, events, alerts, timeline)
    return Response(
        content=content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="case_{case_id}.html"'},
    )


@router.get("/{case_id}/export/pdf")
@_limiter.limit("5/minute")
async def export_pdf(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> Response:
    from oseye.forensic.exporter.pdf_report import export_pdf as _export_pdf
    from oseye.forensic.timeline import build_timeline

    case, events, alerts = await _load_case_bundle(case_id, request)
    timeline = build_timeline(case, events, alerts)
    try:
        pdf_bytes = _export_pdf(case, events, alerts, timeline)
    except ImportError as exc:
        raise HTTPException(
            status_code=501,
            detail=f"PDF export unavailable: {exc}",
        ) from exc
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="case_{case_id}.pdf"'},
    )


@router.get("/{case_id}/export/misp")
@_limiter.limit("10/minute")
async def export_misp(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> dict[str, Any]:
    from oseye.forensic.exporter.misp_export import export_misp_event

    case, _, alerts = await _load_case_bundle(case_id, request)
    return export_misp_event(case, alerts)


@router.get("/{case_id}/export/thehive")
@_limiter.limit("10/minute")
async def export_thehive(
    case_id: UUID,
    request: Request,
    _: dict[str, Any] = Depends(_require_reader),
) -> dict[str, Any]:
    from oseye.forensic.exporter.thehive_export import export_thehive_case

    case, _, alerts = await _load_case_bundle(case_id, request)
    return export_thehive_case(case, alerts)
