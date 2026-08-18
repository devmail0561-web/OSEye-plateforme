"""Threat Intelligence router — /api/v1/ti."""

from __future__ import annotations

import ipaddress
import re
from typing import Any, cast

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from oseye.api.auth.rbac import require_role
from oseye.core.observability import get_logger
from oseye.threat_intel.models import AggregatedTIReport

_logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/ti", tags=["threat-intel"])
limiter = Limiter(key_func=get_remote_address)

_require_analyst_or_admin = require_role("analyst", "admin")

# SEC-TI-001: hash format validation — hex only, lengths 32 (MD5), 40 (SHA-1), 64 (SHA-256)
_HASH_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
_VALID_HASH_LENGTHS = frozenset({32, 40, 64})


def _get_ti_client(request: Request) -> Any:
    client = getattr(request.app.state, "ti_client", None)
    if client is None:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat Intelligence client not initialised",
        )
    return client


@router.get("/lookup", response_model=AggregatedTIReport)
@limiter.limit("30/minute")
async def lookup(
    request: Request,
    ip: str | None = None,
    hash: str | None = None,
    _auth: dict[str, Any] = Depends(_require_analyst_or_admin),
) -> AggregatedTIReport:
    """Look up an IP address or file hash across all configured TI providers.

    Exactly one of *ip* or *hash* must be supplied.
    SEC-TI-001: validates format; rate-limited to 30 requests/minute per IP.
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

    # SEC-TI-001: validate IP format
    if ip is not None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid IP address format",
            )

    # SEC-TI-001: validate hash format
    if hash is not None:
        if not _HASH_RE.fullmatch(hash) or len(hash) not in _VALID_HASH_LENGTHS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Invalid hash value: must be hex-only and exactly 32, 40, or 64 characters"
                ),
            )

    ti_client = _get_ti_client(request)

    try:
        if ip is not None:
            _logger.info("ti_lookup_request", indicator=ip, indicator_type="ip")
            return cast(AggregatedTIReport, await ti_client.lookup(ip, "ip"))

        _logger.info("ti_lookup_request", indicator=hash, indicator_type="hash")
        return cast(AggregatedTIReport, await ti_client.lookup(hash, "hash"))
    except ValueError as exc:
        _logger.error(str(exc))
        raise HTTPException(status_code=400, detail="Threat Intelligence lookup failed") from exc
