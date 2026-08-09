"""Policies router — /api/v1/policies.

Endpoints:
    GET  /api/v1/policies              — list all profiles
    GET  /api/v1/policies/{name}       — get profile by name
    POST /api/v1/policies/{name}/apply — push profile to one or all agents
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from oseye.api.auth.rbac import require_admin, require_analyst
from oseye.core.schema import SurveillanceProfile
from oseye.policy.engine import PolicyEngine

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ApplyRequest(BaseModel):
    agent_id: UUID | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_engine(request: Request) -> PolicyEngine:
    engine: PolicyEngine | None = getattr(request.app.state, "policy_engine", None)
    if engine is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Policy engine not initialised",
        )
    return engine


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("")
async def list_profiles(
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> list[SurveillanceProfile]:
    """Return all loaded surveillance profiles."""
    engine = _get_engine(request)
    return engine.list_profiles()


@router.get("/{name}")
async def get_profile(
    name: str,
    request: Request,
    _auth: dict[str, Any] = Depends(require_analyst),
) -> SurveillanceProfile:
    """Return a single surveillance profile by name."""
    engine = _get_engine(request)
    profile = engine.get_profile(name)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile {name!r} not found",
        )
    return profile


@router.post("/{name}/apply", status_code=status.HTTP_200_OK)
async def apply_profile(
    name: str,
    body: ApplyRequest,
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Push a profile to one agent (agent_id provided) or all known agents.

    Requires the ``admin`` role.
    """
    engine = _get_engine(request)

    if engine.get_profile(name) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile {name!r} not found",
        )

    try:
        if body.agent_id is not None:
            await engine.push_to_agent(body.agent_id, name)
            return {"profile": name, "pushed_to": str(body.agent_id)}
        else:
            await engine.push_to_all(name)
            return {"profile": name, "pushed_to": "all"}
    except KeyError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
