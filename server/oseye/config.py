"""Centralised configuration via pydantic-settings.

All settings are read from environment variables.
Prefix: OSEYE_

Usage:
    from oseye.config import Settings
    settings = Settings()
"""

from __future__ import annotations

from pydantic import Field, model_validator
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
    otel_endpoint: str | None = Field(
        default=None, description="OTLP gRPC endpoint, e.g. localhost:4317"
    )
    service_name: str = Field(default="oseye-server")

    # Worker settings
    batch_flush_interval_ms: int = Field(default=500)
    batch_max_size: int = Field(default=500)

    # Threat Intelligence API keys
    abuseipdb_api_key: str | None = Field(default=None)
    virustotal_api_key: str | None = Field(default=None)
    misp_url: str | None = Field(default=None)
    misp_api_key: str | None = Field(default=None)

    # Threat Intelligence runtime settings
    ti_cache_ttl_seconds: int = 3600
    ti_lookup_timeout_seconds: float = 5.0
    ti_breaker_fail_max: int = 5
    ti_breaker_reset_timeout: float = 60.0

    # Correlation settings
    correlation_window_seconds: int = 300
    correlation_min_severity: str = "medium"

    # Decision Engine settings
    decision_human_timeout_secs: int = 3600
    decision_human_poll_interval: int = 30
    decision_policy_version: str = "v1.0"

    # WeightedScorer weights — must sum to 1.0
    decision_weight_rule:  float = Field(default=0.4, description="Weight for rule score (0–1)")
    decision_weight_ml:    float = Field(default=0.3, description="Weight for ML score (0–1)")
    decision_weight_ti:    float = Field(default=0.2, description="Weight for TI score (0–1)")
    decision_weight_depth: float = Field(default=0.1, description="Weight for correlation depth (0–1)")  # noqa: E501

    # PKI — CA private key (used by enrollment endpoint to sign agent certs)
    tls_ca_key_file: str = Field(default="/etc/oseye/certs/ca.key")

    # Enrollment token directory (one file per token, TTL 24h)
    enrollment_token_dir: str = Field(default="/etc/oseye/enrollment_tokens")

    # Directory of DER-encoded Ed25519 public keys for agent batch signature verification.
    # One file per agent, named {cn}.pub (e.g. "my-agent-hostname.pub").
    agent_keys_dir: str = Field(default="/etc/oseye/agent_keys")

    # Allow insecure gRPC (no TLS/mTLS). NEVER set True in production.
    grpc_insecure_dev: bool = Field(default=False)

    # Surveillance policy settings
    default_surveillance_profile: str = Field(
        default="workstation",
        description="Profile pushed to agents on connect. Must match a builtin profile name.",
    )

    # Plugin system
    plugins_dir: str = Field(
        default="/etc/oseye/plugins",
        description="Directory where plugin .py files are stored.",
    )
    plugin_ipc_socket: str = Field(
        default="/var/run/oseye/plugin.sock",
        description="Unix socket path for plugin IPC (server ↔ plugin NDJSON).",
    )
    plugin_keys_dir: str = Field(
        default="/etc/oseye/plugin_keys",
        description="Directory of Ed25519 .pem public keys used to verify plugin signatures.",
    )
    plugin_require_signature: bool = Field(
        default=True,
        description=(
            "Require a valid Ed25519 signature for every plugin installation. "
            "Set True in production. When True, installations without a valid "
            ".sig file or without a registered trusted key are rejected."
        ),
    )

    # Autonomous agent — local rule engine
    rule_signing_key_path: str | None = Field(
        default=None,
        description=(
            "Path to the Ed25519 PEM private key used to sign RuleSets pushed to agents. "
            "When None, rule sets are pushed unsigned (accepted by agents with nil verify key)."
        ),
    )
    agent_default_autonomy: str = Field(
        default="critical_only",
        description="Fallback autonomy level for profiles not listed in PROFILE_AUTONOMY.",
    )

    @model_validator(mode="after")
    def _validate_weights_sum(self) -> "Settings":
        """PC-08: WeightedScorer weights must sum to 1.0 (±0.001 tolerance)."""
        total = (
            self.decision_weight_rule
            + self.decision_weight_ml
            + self.decision_weight_ti
            + self.decision_weight_depth
        )
        if abs(total - 1.0) > 0.001:
            raise ValueError(
                f"decision_weight_* fields must sum to 1.0; got {total:.6f}. "
                f"(rule={self.decision_weight_rule}, ml={self.decision_weight_ml}, "
                f"ti={self.decision_weight_ti}, depth={self.decision_weight_depth})"
            )
        return self

    # ML Engine
    ml_checkpoint_path: str = Field(
        default="/var/lib/oseye/ml_checkpoint.pkl",
        description="Path for ML model persistence (anomaly detector + MITRE classifier).",
    )
    ml_checkpoint_interval_s: float = Field(
        default=300.0,
        description="Seconds between periodic ML checkpoint saves. 0 disables.",
    )
