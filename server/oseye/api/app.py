"""FastAPI application factory for OSEye API server."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from oseye.api.routers import (
    agents,
    alerts,
    api_keys,
    auth,
    cases,
    decisions,
    enrollment,
    events,
    health,
    incidents,
    plugins,
    policies,
    response_actions,
    rules,
    snapshots,
    ti,
)
from oseye.api.ws.alerts import alerts_ws_manager
from oseye.api.ws.alerts import router as ws_alerts_router
from oseye.config import Settings


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """M-1/M-2: inject security headers on every response.

    CSP mitigates XSS → reduces risk of localStorage token exfiltration.
    X-Frame-Options prevents clickjacking.
    X-Content-Type-Options prevents MIME sniffing.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        )
        return response


def create_app(settings: Settings, *, lifespan: Any = None) -> FastAPI:
    """Build and return the configured FastAPI application."""
    # M-2: disable interactive docs in production (OSEYE_ENV=production)
    import os
    _is_prod = os.getenv("OSEYE_ENV", "development").lower() == "production"

    app = FastAPI(
        title="OSEye API",
        version="0.1.0",
        description="OSEye EDR — REST API",
        lifespan=lifespan,
        docs_url=None if _is_prod else "/docs",
        redoc_url=None if _is_prod else "/redoc",
        openapi_url=None if _is_prod else "/openapi.json",
    )

    # -------------------------------------------------------------------
    # Security headers (M-1: CSP, X-Frame-Options, X-Content-Type-Options)
    # -------------------------------------------------------------------
    app.add_middleware(_SecurityHeadersMiddleware)

    # -------------------------------------------------------------------
    # Rate limiter (SEC-PREV-002)
    # -------------------------------------------------------------------
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # -------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -------------------------------------------------------------------
    # Routers
    # -------------------------------------------------------------------
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(agents.router)
    app.include_router(response_actions.router)
    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(rules.router)
    app.include_router(api_keys.router)
    app.include_router(incidents.router)
    app.include_router(ti.router)
    app.include_router(decisions.router)
    app.include_router(cases.router)
    app.include_router(snapshots.router)
    app.include_router(policies.router)
    app.include_router(plugins.router)
    app.include_router(enrollment.router)
    app.include_router(ws_alerts_router)

    # Expose WS alert manager on app state so RuleWorker and alert endpoints can broadcast
    app.state.ws_alert_manager = alerts_ws_manager

    return app
