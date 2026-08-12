"""Agent enrollment API.

GET  /api/v1/enroll/ca    — return CA cert PEM (token via X-Enrollment-Token header)
POST /api/v1/enroll/sign  — sign agent CSR, return agent cert (token via X-Enrollment-Token header)
"""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/v1", tags=["enrollment"])

limiter = Limiter(key_func=get_remote_address)


class EnrollRequest(BaseModel):
    csr: str = Field(..., max_length=8192, description="PEM-encoded PKCS#10 CSR")
    hostname: str = Field(..., max_length=253, description="Agent hostname (used as CN + SAN)")


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

    The token is NOT consumed by this call — the agent may retry the GET
    if the download is interrupted. The token is consumed on a successful POST.
    """
    store = request.app.state.enrollment_store
    if not store.validate_token(x_enrollment_token):
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
    if not store.validate_token(x_enrollment_token):
        raise HTTPException(status_code=404, detail="Invalid or expired enrollment token")
    try:
        cert_pem = store.sign_csr(body.csr, body.hostname)
    except ValueError:
        raise HTTPException(status_code=422, detail="CSR validation failed") from None
    store.consume_token(x_enrollment_token)
    return {"cert": cert_pem}
