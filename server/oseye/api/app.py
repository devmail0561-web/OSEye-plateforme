"""FastAPI application factory for OSEye API server."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address as _get_remote_address_raw
from starlette.middleware.base import BaseHTTPMiddleware

from oseye.api.routers import (
    agents,
    alerts,
    api_keys,
    auth,
    cases,
    decisions,
    enrollment,
    entities,
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
from oseye.api.ws.decisions import decisions_ws_manager
from oseye.api.ws.decisions import router as ws_decisions_router
from oseye.config import Settings


def _get_real_ip(request: Request) -> str:
    """Extract client IP from X-Forwarded-For when behind a reverse proxy.

    API-04: X-Forwarded-For can be spoofed by clients — only use it when the
    connecting IP is a known trusted proxy (OSEYE_TRUST_PROXY=true).
    When trusted, take the LAST (rightmost) entry which is the closest
    hop added by an actual proxy, not the leftmost which can be forged.
    """
    import os as _os
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for and _os.getenv("OSEYE_TRUST_PROXY", "").lower() == "true":
        # Rightmost entry = closest trusted hop; leftmost can be client-supplied.
        return forwarded_for.split(",")[-1].strip()
    return _get_remote_address_raw(request)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """M-1/M-2: inject security headers on every response.

    CSP mitigates XSS → reduces risk of localStorage token exfiltration.
    X-Frame-Options prevents clickjacking.
    X-Content-Type-Options prevents MIME sniffing.
    """

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        import os as _os
        response: Response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        )
        if _os.getenv("OSEYE_ENV", "development").lower() == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains"
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
    limiter = Limiter(key_func=_get_real_ip)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # -------------------------------------------------------------------
    # CORS — merge api_cors_origins with ui_url if set
    # -------------------------------------------------------------------
    cors_origins = list(settings.api_cors_origins)
    if settings.ui_url and settings.ui_url.rstrip("/") not in cors_origins:
        cors_origins.append(settings.ui_url.rstrip("/"))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Enrollment-Token"],
    )

    # -------------------------------------------------------------------
    # Routers — agent-facing (always registered)
    # -------------------------------------------------------------------
    app.include_router(health.router)
    app.include_router(enrollment.router)

    # -------------------------------------------------------------------
    # Routers — management API (registered only when management_api_active)
    # -------------------------------------------------------------------
    if settings.management_api_active:
        import logging as _log
        _log.getLogger(__name__).info(
            "management_api_enabled",
            ui_dir=settings.ui_dir,
            explicit=settings.management_api_enabled,
        )
        app.include_router(auth.router)
        app.include_router(agents.router)
        app.include_router(response_actions.router)
        app.include_router(events.router)
        app.include_router(entities.router)
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
        app.include_router(ws_alerts_router)
        app.include_router(ws_decisions_router)
        app.state.ws_alert_manager = alerts_ws_manager
        app.state.ws_decision_manager = decisions_ws_manager
    else:
        import logging as _log
        _log.getLogger(__name__).info(
            "management_api_disabled — agent-only mode "
            "(set OSEYE_MANAGEMENT_API_ENABLED=true to enable)"
        )
        app.state.ws_alert_manager = None
        app.state.ws_decision_manager = None

    # -------------------------------------------------------------------
    # Redirect GET / → UI when management API is active and UI is external.
    # Serves as a convenience entry point: the API root redirects to the UI.
    # Not registered when ui_dir is set (StaticFiles handles / instead).
    # -------------------------------------------------------------------
    if settings.management_api_active and settings.ui_url and not settings.ui_dir:
        from fastapi.responses import RedirectResponse

        _ui_redirect = settings.ui_url.rstrip("/")

        @app.get("/", include_in_schema=False)
        async def _root_redirect() -> RedirectResponse:
            return RedirectResponse(url=_ui_redirect, status_code=302)

    # -------------------------------------------------------------------
    # UI static file serving — mounted LAST so API routes take priority.
    # StaticFiles(html=True) serves index.html for any path not matching a file,
    # enabling SPA client-side routing (e.g. /dashboard, /alerts).
    # Only used when the UI is served from THIS server (OSEYE_UI_DIR set).
    # -------------------------------------------------------------------
    if settings.ui_dir:
        from pathlib import Path as _Path

        from starlette.staticfiles import StaticFiles
        _ui = _Path(settings.ui_dir)
        if _ui.is_dir() and (_ui / "index.html").exists():
            app.mount("/", StaticFiles(directory=str(_ui), html=True), name="ui")
        else:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "OSEYE_UI_DIR=%r is not a valid UI dist directory "
                "(missing index.html) — UI not served",
                settings.ui_dir,
            )

    return app
