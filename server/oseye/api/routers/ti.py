"""Threat Intelligence router — /api/v1/ti."""

from __future__ import annotations

from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger
from oseye.threat_intel.models import AggregatedTIReport

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/ti", tags=["threat-intel"])

_require_analyst_or_admin = require_role("analyst", "admin")


def _get_ti_client(request: Request) -> Any:
    client = getattr(request.app.state, "ti_client", None)
    if client is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat Intelligence client not initialised",
        )
    return client


@router.get("/lookup", response_model=AggregatedTIReport)
async def lookup(
    request: Request,
    ip: str | None = None,
    hash: str | None = None,
    _auth: dict[str, Any] = Depends(_require_analyst_or_admin),
) -> AggregatedTIReport:
    """Look up an IP address or file hash across all configured TI providers.

    Exactly one of *ip* or *hash* must be supplied.
    """
    if ip is None and hash is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="At least one of 'ip' or 'hash' query parameters is required",
        )
    if ip is not None and hash is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide either 'ip' or 'hash', not both",
        )

    ti_client = _get_ti_client(request)

    if ip is not None:
        _logger.info("ti_lookup_request", indicator=ip, indicator_type="ip")
        return cast(AggregatedTIReport, await ti_client.lookup(ip, "ip"))

    _logger.info("ti_lookup_request", indicator=hash, indicator_type="hash")
    return cast(AggregatedTIReport, await ti_client.lookup(hash, "hash"))
