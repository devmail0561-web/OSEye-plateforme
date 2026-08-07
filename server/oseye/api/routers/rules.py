"""Rules router — /api/v1/rules."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from oseye.api.auth.rbac import require_admin, require_analyst
from oseye.core.schema import Rule
from oseye.rule_engine.evaluator import _eval_expr
from oseye.rule_engine.models import RuleDefinition

router = APIRouter(prefix="/api/v1", tags=["rules"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RuleValidateRequest(BaseModel):
    condition: str
    timeframe: int | None = None


class RuleValidateResponse(BaseModel):
    valid: bool
    error: str | None = None


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
    with engine._lock:
        rules = list(engine._rules)
    if enabled_only:
        rules = [r for r in rules if r.enabled]
    return {
        "items": [_rule_def_to_schema(r).model_dump(mode="json") for r in rules],
        "total": len(rules),
    }


@router.get("/rules/{rule_id}")
async def get_rule(
    rule_id: str,
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
async def validate_rule(
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
        return RuleValidateResponse(valid=False, error=str(exc))


@router.post("/rules/reload", status_code=status.HTTP_200_OK)
async def reload_rules(
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Reload rules from disk immediately."""
    engine = _get_engine(request)
    count = engine.reload()
    return {"reloaded": count}
