"""Structured logging (structlog JSON) and OpenTelemetry setup."""

from __future__ import annotations

import logging
import sys

import structlog

_configured = False


def configure(log_level: str = "INFO", service_name: str = "oseye-server") -> None:
    """Configure structlog and optionally OpenTelemetry.

    Call once at process startup. Subsequent calls are no-ops.
    """
    global _configured
    if _configured:
        return
    _configured = True

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.ExceptionPrettyPrinter(file=sys.stderr),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(sys.stdout),
        cache_logger_on_first_use=True,
    )

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(service=service_name)


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a structlog bound logger tagged with the given name."""
    logger: structlog.BoundLogger = structlog.get_logger(name)
    return logger
