"""gRPC server factory — creates and starts the async gRPC server with mTLS."""

from __future__ import annotations

import asyncio
import os
from concurrent import futures

import grpc
import grpc.aio

from oseye.bus.interface import EventBus
from oseye.config import Settings
from oseye.core.observability import get_logger
from oseye.ingest.grpc_service import AgentServiceServicer, register_servicer
from oseye.ingest.validator import BatchValidator

_logger = get_logger(__name__)


def _load_tls_credentials(settings: Settings) -> grpc.ServerCredentials | None:
    """Load mTLS credentials from cert files.

    Requires server.crt, server.key, and ca.crt.
    Raises RuntimeError in production if any file is missing.
    Set OSEYE_GRPC_INSECURE_DEV=true to bypass (development only).
    """
    cert_file = settings.tls_cert_file
    key_file = settings.tls_key_file
    ca_file = settings.tls_ca_cert_file

    cert_ok = os.path.exists(cert_file) and os.path.exists(key_file)
    ca_ok = os.path.exists(ca_file)

    if not cert_ok or not ca_ok:
        if settings.grpc_insecure_dev:
            _logger.warning(
                "grpc_server_insecure",
                reason="OSEYE_GRPC_INSECURE_DEV=true",
                missing_cert=not cert_ok,
                missing_ca=not ca_ok,
            )
            return None
        raise RuntimeError(
            "gRPC TLS certificates missing. "
            f"Expected: cert={cert_file}, key={key_file}, ca={ca_file}. "
            "Set OSEYE_GRPC_INSECURE_DEV=true to allow insecure mode (development only)."
        )

    with open(cert_file, "rb") as fh:
        certificate_chain = fh.read()
    with open(key_file, "rb") as fh:
        private_key = fh.read()
    with open(ca_file, "rb") as fh:
        root_ca = fh.read()

    return grpc.ssl_server_credentials(
        [(private_key, certificate_chain)],
        root_certificates=root_ca,
        require_client_auth=True,  # always enforce mTLS when CA is present
    )


async def create_grpc_server(
    settings: Settings, bus: EventBus
) -> tuple[grpc.aio.Server, AgentServiceServicer]:
    """Create a gRPC async server with mTLS.

    Returns (server, servicer) so the servicer can be wired into app.state
    for agent-key registration and blocklist management.

    The server is created and bound but not yet started — call server.start().
    """
    # SEC-CIPHER: restrict to TLS 1.3-only cipher suites via gRPC C-core env.
    # Must be set before the first grpc import creates the C-core channel.
    os.environ.setdefault(
        "GRPC_SSL_CIPHER_SUITES",
        "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
    )

    validator = BatchValidator()
    # SEC-002: pass the running event loop so IngestEvents / ReceivePolicy /
    # StreamCommands can bridge from gRPC's sync threads back to the async bus
    # via run_coroutine_threadsafe instead of the isolated asyncio.run() fallback.
    loop = asyncio.get_event_loop()
    servicer = AgentServiceServicer(
        bus=bus, validator=validator, loop=loop, require_agent_keys=True
    )

    server = grpc.aio.server(
        futures.ThreadPoolExecutor(max_workers=settings.grpc_max_workers),
    )

    register_servicer(servicer, server)

    credentials = _load_tls_credentials(settings)
    listen_addr = f"[::]:{settings.grpc_port}"

    if credentials is not None:
        server.add_secure_port(listen_addr, credentials)
        _logger.info("grpc_server_mtls", address=listen_addr)
    else:
        server.add_insecure_port(listen_addr)
        _logger.warning("grpc_server_insecure", address=listen_addr)

    return server, servicer
