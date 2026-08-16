"""oseye-server setup — interactive configuration wizard."""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from textwrap import dedent
from urllib.parse import quote as _url_quote

from ._pki import DIR_MODES, generate_pki, write_secure
from ._ui import (
    GREEN, BOLD, DIM,
    ask, ask_password, ask_yn,
    c, err, header, ok, step, warn,
)


def run(argv: list[str] | None = None) -> None:  # noqa: ARG001
    header("OSEye Server — Setup Wizard")
    print(c("  This wizard configures your OSEye server after a fresh install.", DIM))
    print(c("  It writes /etc/oseye/server.env and /etc/oseye/secrets.env.", DIM))

    if os.geteuid() != 0:
        err("Must be run as root (sudo oseye-server setup)")
        sys.exit(1)
    if subprocess.run(["openssl", "version"], capture_output=True).returncode != 0:
        err("openssl not found in PATH")
        sys.exit(1)
    if sys.version_info < (3, 12):
        err(f"Python 3.12+ required (got {sys.version})")
        sys.exit(1)

    missing = [d for d in DIR_MODES if not Path(d).is_dir()]
    if missing:
        warn("Missing directories (run 'oseye-server init' first):")
        for d in missing:
            warn(f"  • {d}")
        if not ask_yn("Create them now?", default=True):
            sys.exit(1)
        old_umask = os.umask(0)
        try:
            for d in missing:
                Path(d).mkdir(mode=DIR_MODES[d], parents=True, exist_ok=True)
                ok(f"Created {d}")
        finally:
            os.umask(old_umask)

    TOTAL = 9

    # ── Step 1: Network ───────────────────────────────────────────────────────
    step(1, TOTAL, "Network & hostname")
    hostname = (
        subprocess.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip()
        or subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    )
    ip_out = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.strip()
    ip = ip_out.split()[0] if ip_out else "127.0.0.1"
    hostname  = ask("Server hostname", hostname)
    ip        = ask("Server IP", ip)
    api_port  = ask("API port", "8000")
    grpc_port = ask("gRPC port", "50051")
    cors      = ask("CORS origins (JSON array)", f'["https://{hostname}"]')

    # ── Step 2: PKI ───────────────────────────────────────────────────────────
    step(2, TOTAL, "TLS / PKI")
    certs_dir = Path("/etc/oseye/certs")
    print(c("  Generating PKI (this takes a moment)...", DIM))
    try:
        generated = generate_pki(certs_dir, hostname, ip)
    except ValueError as exc:
        err(str(exc))
        sys.exit(1)
    if generated:
        ok("PKI generated")
    else:
        ok("PKI already present — skipping")

    # ── Step 3: Database ──────────────────────────────────────────────────────
    step(3, TOTAL, "Database")
    print(c("  Options: sqlite (dev/test), postgresql (production)", DIM))
    db_backend = ask("Backend", "postgresql")
    db_user = db_host = db_port_db = db_name = db_password = ""
    if db_backend == "sqlite":
        db_url      = ask("SQLite path", "sqlite+aiosqlite:///./oseye.db")
        db_url_secret = ""
    else:
        db_host      = ask("PostgreSQL host", "localhost")
        db_port_db   = ask("PostgreSQL port", "5432")
        db_name      = ask("Database name", "oseye")
        db_user      = ask("Database user", "oseye")
        db_password  = ask_password("Database password")
        db_url       = f"postgresql+asyncpg://{db_user}@{db_host}:{db_port_db}/{db_name}"
        _pw_encoded  = _url_quote(db_password, safe="")
        db_url_secret = (
            f"\n# Database URL (contains password — keep in this file only)\n"
            f"OSEYE_DB_URL=postgresql+asyncpg://{db_user}:{_pw_encoded}"
            f"@{db_host}:{db_port_db}/{db_name}\n"
        )
    ok(f"Database: {db_backend}")

    # ── Step 4: Redis ─────────────────────────────────────────────────────────
    step(4, TOTAL, "Redis (event bus)")
    redis_url = ask("Redis URL", "redis://localhost:6379/0")
    ok(f"Redis: {redis_url}")

    # ── Step 5: Credentials ───────────────────────────────────────────────────
    step(5, TOTAL, "Admin credentials")
    admin_pw   = ask_password("Admin password (min 12 chars)")
    analyst_pw = ask_password("Analyst password (min 12 chars)")
    secret_key = secrets.token_hex(32)
    ok("Credentials set")

    # ── Step 6: Threat Intelligence (optional) ────────────────────────────────
    step(6, TOTAL, "Threat Intelligence APIs (optional — press Enter to skip)")
    abuseipdb_key  = ask("AbuseIPDB API key", "")
    virustotal_key = ask("VirusTotal API key", "")
    misp_url       = ask("MISP URL", "")
    misp_key       = ask("MISP API key", "") if misp_url else ""
    ti_misp = (
        f"OSEYE_MISP_URL={misp_url}\nOSEYE_MISP_API_KEY={misp_key}"
        if misp_url else "OSEYE_MISP_URL=\nOSEYE_MISP_API_KEY="
    )
    ok("TI providers configured" if any([abuseipdb_key, virustotal_key, misp_url]) else "TI providers skipped")

    # ── Step 7: OpenTelemetry (optional) ──────────────────────────────────────
    step(7, TOTAL, "Observability")
    log_level = ask("Log level", "INFO")
    otel_endpoint = ""
    if ask_yn("Enable OpenTelemetry export?", default=False):
        otel_endpoint = ask("OTLP gRPC endpoint", "localhost:4317")
        ok(f"OTEL endpoint: {otel_endpoint}")
    else:
        ok("OpenTelemetry disabled")
    otel_line = (
        f"OSEYE_OTEL_ENDPOINT={otel_endpoint}" if otel_endpoint
        else "# OSEYE_OTEL_ENDPOINT=localhost:4317"
    )

    # ── Step 8: Surveillance profile ─────────────────────────────────────────
    step(8, TOTAL, "Agent surveillance profile")
    profiles = ["workstation", "server", "minimal", "stealth", "investigation", "compliance"]
    print(c(f"  Available profiles: {', '.join(profiles)}", DIM))
    profile = ask("Default profile", "workstation")
    ok(f"Default profile: {profile}")

    # ── Step 9: Write files ───────────────────────────────────────────────────
    step(9, TOTAL, "Writing configuration files")

    if db_backend == "sqlite":
        db_url_line = f"OSEYE_DB_URL={db_url}"
    else:
        db_url_line = "# OSEYE_DB_URL is in secrets.env (contains password)"

    server_env = dedent(f"""\
        # OSEye Server — Environment Configuration
        # Generated by: oseye-server setup

        # ── Database ─────────────────────────────────────────────────────────
        OSEYE_DB_BACKEND={db_backend}
        {db_url_line}
        OSEYE_DB_POOL_SIZE=10
        OSEYE_DB_MAX_OVERFLOW=20

        # ── Redis ─────────────────────────────────────────────────────────────
        OSEYE_REDIS_URL={redis_url}

        # ── gRPC ──────────────────────────────────────────────────────────────
        OSEYE_GRPC_PORT={grpc_port}
        OSEYE_GRPC_MAX_WORKERS=10

        # ── API ───────────────────────────────────────────────────────────────
        OSEYE_API_PORT={api_port}
        OSEYE_API_HOST=0.0.0.0
        OSEYE_API_CORS_ORIGINS={cors}

        # ── TLS / PKI ─────────────────────────────────────────────────────────
        OSEYE_TLS_CERT_FILE=/etc/oseye/certs/server.crt
        OSEYE_TLS_KEY_FILE=/etc/oseye/certs/server.key
        OSEYE_TLS_CA_CERT_FILE=/etc/oseye/certs/ca.crt
        OSEYE_TLS_CA_KEY_FILE=/etc/oseye/certs/ca.key

        # ── JWT (RS256) ───────────────────────────────────────────────────────
        OSEYE_JWT_PRIVATE_KEY_PATH=/etc/oseye/certs/jwt_private.pem
        OSEYE_JWT_PUBLIC_KEY_PATH=/etc/oseye/certs/jwt_public.pem
        OSEYE_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
        OSEYE_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

        # ── Observability ─────────────────────────────────────────────────────
        OSEYE_LOG_LEVEL={log_level}
        OSEYE_SERVICE_NAME=oseye-server
        {otel_line}

        # ── Workers ───────────────────────────────────────────────────────────
        OSEYE_BATCH_FLUSH_INTERVAL_MS=500
        OSEYE_BATCH_MAX_SIZE=500

        # ── Enrollment ────────────────────────────────────────────────────────
        OSEYE_ENROLLMENT_TOKEN_DEFAULT_TTL_HOURS=24

        # ── Threat Intelligence ───────────────────────────────────────────────
        OSEYE_TI_CACHE_TTL_SECONDS=3600
        OSEYE_TI_LOOKUP_TIMEOUT_SECONDS=5.0
        OSEYE_TI_BREAKER_FAIL_MAX=5
        OSEYE_TI_BREAKER_RESET_TIMEOUT=60.0

        # ── Correlation ───────────────────────────────────────────────────────
        OSEYE_CORRELATION_WINDOW_SECONDS=300
        OSEYE_CORRELATION_MIN_SEVERITY=medium

        # ── Decision Engine ───────────────────────────────────────────────────
        OSEYE_DECISION_HUMAN_TIMEOUT_SECS=3600
        OSEYE_DECISION_HUMAN_POLL_INTERVAL=30
        OSEYE_DECISION_POLICY_VERSION=v1.0

        # ── Agent surveillance ────────────────────────────────────────────────
        OSEYE_DEFAULT_SURVEILLANCE_PROFILE={profile}

        # ── Production guard ──────────────────────────────────────────────────
        OSEYE_ENV=production
    """)

    secrets_env = dedent(f"""\
        # OSEye Server — SECRETS
        # Generated by: oseye-server setup
        # chmod 600, owner root — NEVER commit this file.

        OSEYE_SECRET_KEY={secret_key}
        OSEYE_TLS_CA_KEY_PASSWORD=

        OSEYE_ADMIN_PASSWORD={admin_pw}
        OSEYE_ANALYST_PASSWORD={analyst_pw}

        OSEYE_DB_PASSWORD={db_password}{db_url_secret}
        OSEYE_ABUSEIPDB_API_KEY={abuseipdb_key}
        OSEYE_VIRUSTOTAL_API_KEY={virustotal_key}
        {ti_misp}
    """)

    write_secure(Path("/etc/oseye/server.env"), server_env, 0o640)
    ok("Written /etc/oseye/server.env (mode 640)")

    write_secure(Path("/etc/oseye/secrets.env"), secrets_env, 0o600)
    ok("Written /etc/oseye/secrets.env (mode 600)")

    token = secrets.token_hex(32)
    write_secure(Path("/etc/oseye/enrollment_tokens") / token, str(int(time.time())), 0o600)
    ok("Enrollment token generated")

    width = 64
    lines = [
        f"  Server    : {hostname}",
        f"  API       : https://{hostname}:{api_port}",
        f"  gRPC      : {hostname}:{grpc_port}",
        f"  DB        : {db_backend}",
        "",
        "  Enrollment token (valid 24 h):",
        f"  {token}",
        "",
        "  To enroll an agent:",
        f"    oseye-config enroll --server {hostname}:{api_port} --token {token}",
        "",
        "  Start server:",
        "    oseye-server start",
    ]
    print()
    print(c("┌" + "─" * (width - 2) + "┐", GREEN, BOLD))
    print(c(f"│{'  Setup complete':^{width - 2}}│", GREEN, BOLD))
    print(c("├" + "─" * (width - 2) + "┤", GREEN, BOLD))
    for line in lines:
        print(c(f"│ {line:<{width - 3}}│", GREEN))
    print(c("└" + "─" * (width - 2) + "┘", GREEN, BOLD))
    print()
