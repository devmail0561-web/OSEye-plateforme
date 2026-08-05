"""Centralised configuration via pydantic-settings.

All settings are read from environment variables.
Prefix: OSEYE_

Usage:
    from oseye.config import Settings
    settings = Settings()
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OSEYE_", case_sensitive=False)

    # Database
    db_backend: str = Field(default="sqlite", description="sqlite | postgresql | clickhouse")
    db_url: str = Field(default="sqlite+aiosqlite:///./oseye_dev.db")
    db_pool_size: int = 10
    db_max_overflow: int = 20

    # Redis (event bus)
    redis_url: str = Field(default="redis://localhost:6379/0")

    # gRPC server
    grpc_port: int = Field(default=50051)
    grpc_max_workers: int = Field(default=10)

    # API server
    api_port: int = Field(default=8000)
    api_host: str = Field(default="0.0.0.0")
    api_cors_origins: list[str] = Field(default=["http://localhost:5173"])

    # TLS / PKI
    tls_cert_file: str = Field(default="/etc/oseye/certs/server.crt")
    tls_key_file: str = Field(default="/etc/oseye/certs/server.key")
    tls_ca_cert_file: str = Field(default="/etc/oseye/certs/ca.crt")

    # JWT authentication (RS256)
    jwt_private_key_path: str = Field(default="/etc/oseye/certs/jwt_private.pem")
    jwt_public_key_path: str = Field(default="/etc/oseye/certs/jwt_public.pem")
    jwt_access_token_expire_minutes: int = Field(default=15)
    jwt_refresh_token_expire_days: int = Field(default=7)

    # Observability
    log_level: str = Field(default="INFO")
    otel_endpoint: str | None = Field(default=None, description="OTLP gRPC endpoint e.g. localhost:4317")
    service_name: str = Field(default="oseye-server")

    # Worker settings
    batch_flush_interval_ms: int = Field(default=500)
    batch_max_size: int = Field(default=500)

    # Threat Intelligence API keys
    abuseipdb_api_key: str | None = Field(default=None)
    virustotal_api_key: str | None = Field(default=None)
    misp_url: str | None = Field(default=None)
    misp_api_key: str | None = Field(default=None)
