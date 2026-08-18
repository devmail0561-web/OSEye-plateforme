"""Agent enrollment API.

POST   /api/v1/enroll/tokens           — generate an enrollment token (admin)
GET    /api/v1/enroll/tokens           — list active tokens (admin)
DELETE /api/v1/enroll/tokens/{tok_id}  — revoke a token (admin)
GET    /api/v1/enroll/ca               — return CA cert PEM (X-Enrollment-Token)
POST   /api/v1/enroll/sign             — sign agent CSR, return cert (X-Enrollment-Token)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request, Response, status
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from oseye.api.auth.rbac import require_admin

router = APIRouter(prefix="/api/v1", tags=["enrollment"])

limiter = Limiter(key_func=get_remote_address)

_UUID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


# ------------------------------------------------------------------
# Admin — token management
# ------------------------------------------------------------------

class TokenCreateBody(BaseModel):
    expires_in_hours: int | None = Field(
        default=None,
        ge=1,
        le=8760,  # 1 year max
        description=(
            "TTL in hours. Omit to use the server default "
            "(OSEYE_ENROLLMENT_TOKEN_DEFAULT_TTL_HOURS)."
        ),
    )


@router.post("/enroll/tokens", status_code=status.HTTP_201_CREATED)
@limiter.limit("20/minute")
async def create_enrollment_token(
    body: TokenCreateBody,
    request: Request,
    auth: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """Generate a one-time enrollment token (admin only).

    Returns the raw token (shown once — never stored) and its token_id.
    Pass the token to the agent via OSEYE_ENROLL_TOKEN.
    """
    store = request.app.state.enrollment_store
    created_by = str(auth.get("sub", "unknown"))
    raw, token_id = await store.create_token(
        created_by=created_by,
        ttl_hours=body.expires_in_hours,
    )
    return {"token": raw, "token_id": token_id}


@router.get("/enroll/tokens")
@limiter.limit("60/minute")
async def list_enrollment_tokens(
    request: Request,
    _auth: dict[str, Any] = Depends(require_admin),
) -> list[dict]:
    """List active (non-expired) enrollment tokens (admin only).

    Raw token values are never returned — only token_id, dates, and creator.
    """
    store = request.app.state.enrollment_store
    return await store.list_tokens()


@router.delete("/enroll/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("20/minute")
async def revoke_enrollment_token(
    token_id: str = Path(pattern=_UUID_RE),
    request: Request = ...,
    _auth: dict[str, Any] = Depends(require_admin),
) -> None:
    """Revoke an enrollment token before it is used (admin only)."""
    store = request.app.state.enrollment_store
    if not await store.revoke_token(token_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")


# ------------------------------------------------------------------
# Agent — enrollment flow
# ------------------------------------------------------------------

class EnrollRequest(BaseModel):
    csr: str = Field(..., max_length=8192, description="PEM-encoded PKCS#10 CSR")
    hostname: str = Field(
        ...,
        max_length=253,
        pattern=r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$",
        description="Agent hostname (used as CN + SAN)",
    )


@router.get(
    "/enroll/ca",
    summary="Fetch CA certificate",
    response_class=Response,
    responses={200: {"content": {"application/x-pem-file": {}}}, 404: {}},
)
@limiter.limit("5/minute")
async def get_ca_cert(
    request: Request,
    x_enrollment_token: str = Header(..., alias="X-Enrollment-Token"),
) -> Response:
    """Return the server CA certificate if the enrollment token is valid.

    The token is NOT consumed by this call — the agent may retry if interrupted.
    """
    store = request.app.state.enrollment_store
    if not await store.validate_token(x_enrollment_token):
        raise HTTPException(status_code=404, detail="Invalid or expired enrollment token")
    return Response(content=store.get_ca_cert_pem(), media_type="application/x-pem-file")


@router.post(
    "/enroll/sign",
    summary="Sign agent CSR",
    responses={200: {"description": "Signed agent certificate"}, 404: {}, 422: {}},
)
@limiter.limit("5/minute")
async def sign_agent_csr(
    request: Request,
    body: EnrollRequest,
    x_enrollment_token: str = Header(..., alias="X-Enrollment-Token"),
) -> dict[str, str]:
    """Sign the agent CSR with the server CA key.

    The enrollment token is consumed (one-time use) after successful signing.
    """
    store = request.app.state.enrollment_store
    # NE-R-05: atomic validate+consume at DB level — no TOCTOU race.
    if not await store.validate_and_consume(x_enrollment_token):
        raise HTTPException(status_code=404, detail="Invalid or expired enrollment token")
    try:
        cert_pem = store.sign_csr(body.csr, body.hostname)
    except ValueError:
        raise HTTPException(status_code=422, detail="CSR validation failed") from None
    return {"cert": cert_pem}
