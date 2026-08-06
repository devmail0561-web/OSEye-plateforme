"""FastAPI application factory for OSEye API server."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from oseye.api.routers import alerts, auth, events, health
from oseye.config import Settings


def create_app(settings: Settings) -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(
        title="OSEye API",
        version="0.1.0",
        description="OSEye EDR — REST API",
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

    return app
