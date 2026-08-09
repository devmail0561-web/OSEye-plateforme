"""FastAPI application factory for OSEye API server."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from oseye.api.routers import (
    alerts,
    api_keys,
    auth,
    cases,
    decisions,
    events,
    health,
    incidents,
    plugins,
    policies,
    rules,
    snapshots,
    ti,
)
from oseye.api.ws.alerts import alerts_ws_manager
from oseye.api.ws.alerts import router as ws_alerts_router
from oseye.config import Settings


def create_app(settings: Settings, *, lifespan: Any = None) -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(
        title="OSEye API",
        version="0.1.0",
        description="OSEye EDR — REST API",
        lifespan=lifespan,
    )

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
    app.include_router(ws_alerts_router)

    # Expose WS alert manager on app state so RuleWorker and alert endpoints can broadcast
    app.state.ws_alert_manager = alerts_ws_manager

    return app
