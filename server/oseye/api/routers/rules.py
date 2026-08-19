"""Rules router — /api/v1/rules."""

from __future__ import annotations

import json
import os as _os
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel, Field
from slowapi import Limiter

from oseye.api.auth.rbac import require_admin, require_analyst
from oseye.core.schema import Rule
from oseye.rule_engine.evaluator import _eval_expr
from oseye.rule_engine.models import RuleDefinition
from oseye.storage.models import RuleRow
from oseye.storage.repositories.rules import SQLRuleRepository

router = APIRouter(prefix="/api/v1", tags=["rules"])


def _get_ip(request):
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for and _os.getenv("OSEYE_TRUST_PROXY", "").lower() == "true":
        return forwarded_for.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"

_limiter = Limiter(key_func=_get_ip)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RuleValidateRequest(BaseModel):
    condition: str
    timeframe: int | None = None


class RuleValidateResponse(BaseModel):
    valid: bool
    error: str | None = None


class RuleCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    rule_type: Literal["anomaly", "surveillance"] = "anomaly"
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    config_json: str = "{}"
    yaml_content: str = ""
    profile_id: str | None = None
    enabled: bool = True
    author: str | None = None


class RuleUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=256)
    rule_type: Literal["anomaly", "surveillance"] | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None
    priority: Literal["low", "medium", "high", "critical"] | None = None
    config_json: str | None = None
    yaml_content: str | None = None
    profile_id: str | None = None
    enabled: bool | None = None


class RuleDBResponse(BaseModel):
    rule_id: str
    name: str
    rule_type: str
    severity: str
    priority: str
    config_json: str
    yaml_content: str
    version: int
    profile_id: str | None
    enabled: bool
    created_at: str
    updated_at: str
    author: str | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_engine(request: Request) -> Any:
    engine = getattr(request.app.state, "rule_engine", None)
    if engine is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rule engine not initialised",
        )
    return engine


def _get_rule_repo(request: Request) -> SQLRuleRepository:
    repo = getattr(request.app.state, "rule_repo", None)
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rule repository not initialised",
        )
    return repo


def _row_to_resp(row: RuleRow) -> RuleDBResponse:
    return RuleDBResponse(
        rule_id=row.rule_id,
        name=row.name,
        rule_type=row.rule_type,
        severity=row.severity,
        priority=row.priority,
        config_json=row.config_json,
        yaml_content=row.yaml_content,
        version=row.version,
        profile_id=row.profile_id,
        enabled=row.enabled,
        created_at=row.created_at,
        updated_at=row.updated_at,
        author=row.author,
    )


def _rule_def_to_schema(r: RuleDefinition) -> Rule:
    return Rule(
        id=r.id,
        name=r.name,
        enabled=r.enabled,
        severity=r.severity,  # type: ignore[arg-type]
        condition_yaml=r.condition,
        timeframe=r.timeframe,
        actions=r.actions,
        tags=r.tags,
        mitre=r.mitre,
        explanation=r.explanation,
        source=r.source,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/rules")
async def list_rules(
    request: Request,
    enabled_only: bool = False,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """List all loaded rules."""
    engine = _get_engine(request)
    # BUG-008: use the public list_rules() method instead of accessing _lock/_rules.
    rules: list[RuleDefinition] = engine.list_rules()
    if enabled_only:
        rules = [r for r in rules if r.enabled]
    return {
        "items": [_rule_def_to_schema(r).model_dump(mode="json") for r in rules],
        "total": len(rules),
    }


@router.get("/rules/db", status_code=status.HTTP_200_OK)
async def list_db_rules(
    request: Request,
    enabled_only: bool = False,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """List all admin-managed rules from DB."""
    repo = _get_rule_repo(request)
    rows = await repo.list(enabled_only=enabled_only)
    return {
        "items": [_row_to_resp(r).model_dump() for r in rows],
        "total": len(rows),
    }


@router.get("/rules/db/{rule_id}", status_code=status.HTTP_200_OK)
async def get_db_rule(
    rule_id: Annotated[str, Path(max_length=64)],
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> RuleDBResponse:
    """Return a single admin-managed rule by ID."""
    repo = _get_rule_repo(request)
    row = await repo.get(rule_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _row_to_resp(row)


@router.get("/rules/{rule_id}")
async def get_rule(
    # API-07: enforce max length on path param to prevent oversized lookups.
    rule_id: Annotated[str, Path(max_length=100)],
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> Rule:
    """Return a single rule by ID."""
    engine = _get_engine(request)
    rule = engine.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _rule_def_to_schema(rule)


@router.post("/rules/validate", status_code=status.HTTP_200_OK)
@_limiter.limit("20/minute")
async def validate_rule(
    request: Request,
    body: RuleValidateRequest,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> RuleValidateResponse:
    """Validate a rule condition expression without saving it."""
    try:
        # Use a minimal synthetic event dict
        dummy: dict[str, object] = {
            "category": "process", "type": "exec", "severity": "info",
            "uid": 0, "pid": 1, "executable": "/bin/true", "resource": "",
            "hostname": "test", "dst_port": 0, "result": "success",
            "process_name": "", "cmdline": "", "os": "linux",
        }
        _eval_expr(body.condition, dummy, rule_id="__validate__")
        return RuleValidateResponse(valid=True)
    except Exception as exc:  # noqa: BLE001
        # SEC-INFO-001: return a generic error category, not the raw exception
        # message, to avoid leaking internal evaluator details to callers.
        msg = str(exc)
        if "SyntaxError" in type(exc).__name__ or "syntax" in msg.lower():
            safe_error = "Syntax error in condition expression"
        elif "NameError" in type(exc).__name__ or "not allowed" in msg.lower():
            safe_error = "Forbidden expression or identifier in condition"
        elif "TypeError" in type(exc).__name__:
            safe_error = "Type error in condition expression"
        else:
            safe_error = "Invalid condition expression"
        return RuleValidateResponse(valid=False, error=safe_error)


@router.post("/rules/reload", status_code=status.HTTP_200_OK)
async def reload_rules(
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Reload rules from disk immediately."""
    engine = _get_engine(request)
    count = engine.reload()
    return {"reloaded": count}


# ---------------------------------------------------------------------------
# CRUD endpoints (DB-backed rules configured via UI/CLI)
# ---------------------------------------------------------------------------


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: Request,
    body: RuleCreateRequest,
    _auth: dict[str, Any] = Depends(require_admin),
) -> RuleDBResponse:
    """Create a new admin-managed rule."""
    repo = _get_rule_repo(request)
    now = datetime.now(UTC).isoformat()
    row = RuleRow(
        rule_id=str(uuid.uuid4()),
        name=body.name,
        rule_type=body.rule_type,
        severity=body.severity,
        priority=body.priority,
        config_json=body.config_json,
        yaml_content=body.yaml_content,
        version=1,
        profile_id=body.profile_id,
        enabled=body.enabled,
        created_at=now,
        updated_at=now,
        author=body.author,
    )
    created = await repo.create(row)
    return _row_to_resp(created)


@router.put("/rules/db/{rule_id}", status_code=status.HTTP_200_OK)
async def update_db_rule(
    rule_id: Annotated[str, Path(max_length=64)],
    request: Request,
    body: RuleUpdateRequest,
    _auth: dict[str, Any] = Depends(require_admin),
) -> RuleDBResponse:
    """Update an admin-managed rule. Version is incremented automatically."""
    repo = _get_rule_repo(request)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="No fields to update")
    row = await repo.update(rule_id, **updates)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _row_to_resp(row)


@router.delete("/rules/db/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_db_rule(
    rule_id: Annotated[str, Path(max_length=64)],
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> None:
    """Delete an admin-managed rule (admin only)."""
    repo = _get_rule_repo(request)
    deleted = await repo.delete(rule_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")


class RuleHistoryEntry(BaseModel):
    id: int
    rule_id: str
    version: int
    change_type: str
    diff_json: str | None
    author: str | None
    changed_at: str
    yaml_snapshot: str | None


class AssignProfileRequest(BaseModel):
    profile_id: str = Field(min_length=1, max_length=64)


@router.get("/rules/db/{rule_id}/history", status_code=status.HTTP_200_OK)
async def get_rule_history(
    rule_id: Annotated[str, Path(max_length=64)],
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> dict[str, Any]:
    """Return the change history for a DB-managed rule (including deleted rules)."""
    repo = _get_rule_repo(request)
    entries = await repo.get_history(rule_id)
    if not entries:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return {
        "rule_id": rule_id,
        "items": [
            RuleHistoryEntry(
                id=e.id,
                rule_id=e.rule_id,
                version=e.version,
                change_type=e.change_type,
                diff_json=e.diff_json,
                author=e.author,
                changed_at=e.changed_at,
                yaml_snapshot=e.yaml_snapshot,
            ).model_dump()
            for e in entries
        ],
        "total": len(entries),
    }


@router.post("/rules/db/{rule_id}/assign-profile", status_code=status.HTTP_200_OK)
async def assign_rule_to_profile(
    rule_id: Annotated[str, Path(max_length=64)],
    request: Request,
    body: AssignProfileRequest,
    _auth: dict[str, Any] = Depends(require_admin),
) -> RuleDBResponse:
    """Assign a rule to a profile — metadata-only operation (P9 versioning/audit).

    Updates profile_id in the rules_db table. This has NO effect on live rule
    evaluation, which remains YAML-driven (RuleEngine reads from disk). The
    assignment is recorded in the change log and survives restarts as metadata.
    """
    repo = _get_rule_repo(request)
    row = await repo.update(rule_id, profile_id=body.profile_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return _row_to_resp(row)
