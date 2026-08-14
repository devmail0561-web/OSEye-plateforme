"""Rules router — /api/v1/rules."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address

from oseye.api.auth.rbac import require_admin, require_analyst
from oseye.core.schema import Rule
from oseye.rule_engine.evaluator import _eval_expr
from oseye.rule_engine.models import RuleDefinition

router = APIRouter(prefix="/api/v1", tags=["rules"])
_limiter = Limiter(key_func=get_remote_address)


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
    # BUG-008: use the public list_rules() method instead of accessing _lock/_rules.
    rules: list[RuleDefinition] = engine.list_rules()
    if enabled_only:
        rules = [r for r in rules if r.enabled]
    return {
        "items": [_rule_def_to_schema(r).model_dump(mode="json") for r in rules],
        "total": len(rules),
    }


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
