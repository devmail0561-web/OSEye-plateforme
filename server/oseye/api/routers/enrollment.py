"""Agent enrollment API.

GET  /api/v1/enroll/{token}  — return CA cert PEM (does not consume token)
POST /api/v1/enroll/{token}  — sign agent CSR, return agent cert (consumes token)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1", tags=["enrollment"])


class EnrollRequest(BaseModel):
    csr: str = Field(..., description="PEM-encoded PKCS#10 CSR")
    hostname: str = Field(..., max_length=253, description="Agent hostname (used as CN + SAN)")


@router.get(
    "/enroll/{token}",
    summary="Fetch CA certificate",
    response_class=Response,
    responses={200: {"content": {"application/x-pem-file": {}}}, 404: {}},
)
async def get_ca_cert(token: str, request: Request) -> Response:
    """Return the server CA certificate if the enrollment token is valid.

    The token is NOT consumed by this call — the agent may retry the GET
    if the download is interrupted. The token is consumed on a successful POST.
    """
    store = request.app.state.enrollment_store
    if not store.validate_token(token):
        raise HTTPException(status_code=404, detail="Invalid or expired enrollment token")
    return Response(content=store.get_ca_cert_pem(), media_type="application/x-pem-file")


@router.post(
    "/enroll/{token}",
    summary="Sign agent CSR",
    responses={200: {"description": "Signed agent certificate"}, 404: {}, 422: {}},
)
async def sign_agent_csr(
    token: str, body: EnrollRequest, request: Request
) -> dict[str, str]:
    """Sign the agent CSR with the server CA key.

    The enrollment token is consumed (one-time use) after successful signing.
    """
    store = request.app.state.enrollment_store
    if not store.validate_token(token):
        raise HTTPException(status_code=404, detail="Invalid or expired enrollment token")
    try:
        cert_pem = store.sign_csr(body.csr, body.hostname)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.consume_token(token)
    return {"cert": cert_pem}
