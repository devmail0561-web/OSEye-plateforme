"""Structured logging (structlog JSON) and OpenTelemetry setup."""

from __future__ import annotations

import logging
import os
import sys

import structlog
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter

_configured = False


def configure(log_level: str = "INFO", service_name: str = "oseye-server") -> None:
    """Configure structlog and OpenTelemetry.

    Call once at process startup. Subsequent calls are no-ops.

    OpenTelemetry setup:
    - If OTEL_EXPORTER_OTLP_ENDPOINT is set: exports to OTLP collector
    - Otherwise: exports to console (dev/test mode)
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
            structlog.processors.format_exc_info,
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

    resource = Resource(attributes={SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    # OSEYE_OTEL_INSECURE takes priority over the generic OTEL_INSECURE so it is
    # visible to 'oseye-server validate' and properly namespaced (audit L-26).
    insecure = (
        os.getenv("OSEYE_OTEL_INSECURE", os.getenv("OTEL_INSECURE", "false")).lower() == "true"
    )
    exporter: SpanExporter
    if otlp_endpoint:
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=insecure)
    else:
        exporter = ConsoleSpanExporter()

    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def get_logger(name: str) -> structlog.BoundLogger:
    """Return a structlog bound logger tagged with the given name."""
    logger: structlog.BoundLogger = structlog.get_logger(name)
    return logger
