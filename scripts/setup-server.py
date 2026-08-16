#!/usr/bin/env python3
"""OSEye Server — Interactive Setup Wizard.

Guides the operator through all configuration steps after a fresh installation
and writes /etc/oseye/server.env + /etc/oseye/secrets.env.

Usage:
    sudo python3 scripts/setup-server.py
"""

from __future__ import annotations

import getpass
import os
import secrets
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

# ── ANSI helpers ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"
WHITE  = "\033[97m"
BG_DARK = "\033[48;5;235m"

def c(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET

def header(title: str) -> None:
    width = 64
    print()
    print(c("┌" + "─" * (width - 2) + "┐", CYAN, BOLD))
    print(c(f"│  {title:<{width - 4}}│", CYAN, BOLD))
    print(c("└" + "─" * (width - 2) + "┘", CYAN, BOLD))

def step(n: int, total: int, title: str) -> None:
    print()
    print(c(f"  [{n}/{total}] {title}", BOLD, WHITE))
    print(c("  " + "─" * 56, DIM))

def ok(msg: str) -> None:
    print(c(f"  ✓ {msg}", GREEN))

def warn(msg: str) -> None:
    print(c(f"  ! {msg}", YELLOW))

def err(msg: str) -> None:
    print(c(f"  ✗ {msg}", RED), file=sys.stderr)

def ask(prompt: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    try:
        val = input(c(f"  → {prompt}{hint}: ", CYAN)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val or default

def ask_password(prompt: str) -> str:
    while True:
        try:
            pw = getpass.getpass(c(f"  → {prompt}: ", CYAN))
            if len(pw) < 12:
                warn("Password must be at least 12 characters.")
                continue
            confirm = getpass.getpass(c("  → Confirm: ", CYAN))
            if pw != confirm:
                warn("Passwords do not match.")
                continue
            return pw
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)

def ask_yn(prompt: str, default: bool = False) -> bool:
    hint = "[Y/n]" if default else "[y/N]"
    try:
        val = input(c(f"  → {prompt} {hint}: ", CYAN)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return (val in ("y", "yes")) if val else default

# ── Prerequisites ─────────────────────────────────────────────────────────────

def check_prereqs() -> None:
    issues: list[str] = []
    if os.geteuid() != 0:
        issues.append("Must be run as root (sudo python3 scripts/setup-server.py)")
    if subprocess.run(["openssl", "version"], capture_output=True).returncode != 0:
        issues.append("openssl not found in PATH")
    if sys.version_info < (3, 12):
        issues.append(f"Python 3.12+ required (got {sys.version})")
    if issues:
        err("Prerequisites not met:")
        for i in issues:
            err(f"  • {i}")
        sys.exit(1)

_DIR_MODES: dict[str, int] = {
    "/etc/oseye/certs":             0o700,
    "/etc/oseye/enrollment_tokens": 0o700,
    "/etc/oseye/agent_keys":        0o700,
    "/etc/oseye/plugins":           0o750,
    "/etc/oseye/plugin_keys":       0o700,
    "/var/lib/oseye":               0o750,
    "/var/run/oseye":               0o755,
}

def check_dirs() -> None:
    missing = [d for d in _DIR_MODES if not Path(d).is_dir()]
    if missing:
        warn("Missing directories (run init-server.sh first):")
        for d in missing:
            warn(f"  • {d}")
        if not ask_yn("Create them now?", default=True):
            sys.exit(1)
        for d in missing:
            Path(d).mkdir(mode=_DIR_MODES[d], parents=True, exist_ok=True)
            ok(f"Created {d}")

# ── PKI generation ────────────────────────────────────────────────────────────

def _run(cmd: list[str], *, check: bool = True) -> None:
    subprocess.run(cmd, capture_output=True, check=check)

def _write_secure(path: Path, content: str, mode: int) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(content)

def generate_pki(certs_dir: Path, hostname: str, ip: str) -> None:
    if "/" in hostname or " " in hostname:
        raise ValueError(f"Invalid hostname {hostname!r}: must not contain '/' or spaces")

    ca_crt = certs_dir / "ca.crt"
    if ca_crt.exists():
        ok("PKI already present — skipping generation")
        return

    old_umask = os.umask(0o077)
    try:
        print(c("  Generating CA (4096-bit, 10 years)...", DIM))
        _run(["openssl", "genrsa", "-out", str(certs_dir / "ca.key"), "4096"])
        _run(["openssl", "req", "-new", "-x509", "-days", "3650",
              "-key", str(certs_dir / "ca.key"),
              "-out", str(certs_dir / "ca.crt"),
              "-subj", "/CN=OSEye-CA/O=OSEye/C=FR"])
        ok("CA generated")

        print(c("  Generating server certificate (4096-bit, 825 days)...", DIM))
        san = f"subjectAltName=DNS:{hostname},DNS:localhost,IP:{ip},IP:127.0.0.1"
        san_file = certs_dir / "san.tmp"
        _write_secure(san_file, san, 0o600)
        _run(["openssl", "genrsa", "-out", str(certs_dir / "server.key"), "4096"])
        _run(["openssl", "req", "-new",
              "-key", str(certs_dir / "server.key"),
              "-out", str(certs_dir / "server.csr"),
              "-subj", f"/CN={hostname}/O=OSEye/C=FR"])
        _run(["openssl", "x509", "-req", "-days", "825",
              "-in", str(certs_dir / "server.csr"),
              "-CA", str(certs_dir / "ca.crt"),
              "-CAkey", str(certs_dir / "ca.key"),
              "-CAcreateserial",
              "-out", str(certs_dir / "server.crt"),
              "-extfile", str(san_file)])
        san_file.unlink(missing_ok=True)
        (certs_dir / "server.csr").unlink(missing_ok=True)
        ok("Server certificate generated")

        print(c("  Generating JWT RS256 key pair (4096-bit)...", DIM))
        _run(["openssl", "genrsa", "-out", str(certs_dir / "jwt_private.pem"), "4096"])
        _run(["openssl", "rsa", "-in", str(certs_dir / "jwt_private.pem"),
              "-pubout", "-out", str(certs_dir / "jwt_public.pem")])
        ok("JWT key pair generated")
    finally:
        os.umask(old_umask)

# ── Enrollment token ──────────────────────────────────────────────────────────

def generate_enrollment_token(token_dir: Path) -> str:
    import time
    token = secrets.token_hex(32)
    _write_secure(token_dir / token, str(int(time.time())), 0o600)
    return token

# ── Main wizard ───────────────────────────────────────────────────────────────

def main() -> None:
    header("OSEye Server — Setup Wizard")
    print(c("  This wizard configures your OSEye server after a fresh install.", DIM))
    print(c("  It writes /etc/oseye/server.env and /etc/oseye/secrets.env.", DIM))

    TOTAL = 9

    # 0. Prereqs
    check_prereqs()
    check_dirs()

    # ── Step 1: Network ───────────────────────────────────────────────────────
    step(1, TOTAL, "Network & hostname")
    hostname = subprocess.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip() \
               or subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    ip_out = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.strip()
    ip = ip_out.split()[0] if ip_out else "127.0.0.1"

    hostname = ask("Server hostname", hostname)
    ip       = ask("Server IP", ip)
    api_port  = ask("API port", "8000")
    grpc_port = ask("gRPC port", "50051")
    cors      = ask("CORS origins (JSON array)", f'["https://{hostname}"]')

    # ── Step 2: PKI ───────────────────────────────────────────────────────────
    step(2, TOTAL, "TLS / PKI")
    certs_dir = Path("/etc/oseye/certs")
    generate_pki(certs_dir, hostname, ip)

    # ── Step 3: Database ──────────────────────────────────────────────────────
    step(3, TOTAL, "Database")
    print(c("  Options: sqlite (dev/test), postgresql (production)", DIM))
    db_backend = ask("Backend", "postgresql")
    if db_backend == "sqlite":
        db_url      = ask("SQLite path", "sqlite+aiosqlite:///./oseye.db")
        db_password = ""
    else:
        db_host = ask("PostgreSQL host", "localhost")
        db_port = ask("PostgreSQL port", "5432")
        db_name = ask("Database name", "oseye")
        db_user = ask("Database user", "oseye")
        db_password = ask_password("Database password")
        db_url = f"postgresql+asyncpg://{db_user}@{db_host}:{db_port}/{db_name}"
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
    if any([abuseipdb_key, virustotal_key, misp_url]):
        ok("TI providers configured")
    else:
        ok("TI providers skipped")

    # ── Step 7: OpenTelemetry (optional) ──────────────────────────────────────
    step(7, TOTAL, "Observability")
    log_level    = ask("Log level", "INFO")
    otel_enabled = ask_yn("Enable OpenTelemetry export?", default=False)
    otel_endpoint = ""
    if otel_enabled:
        otel_endpoint = ask("OTLP gRPC endpoint", "localhost:4317")
        ok(f"OTEL endpoint: {otel_endpoint}")
    else:
        ok("OpenTelemetry disabled")

    # ── Step 8: Surveillance profile ─────────────────────────────────────────
    step(8, TOTAL, "Agent surveillance profile")
    profiles = ["workstation", "server", "minimal", "stealth", "investigation", "compliance"]
    print(c(f"  Available profiles: {', '.join(profiles)}", DIM))
    profile = ask("Default profile", "workstation")
    ok(f"Default profile: {profile}")

    # ── Step 9: Write files ───────────────────────────────────────────────────
    step(9, TOTAL, "Writing configuration files")

    otel_line = f"OSEYE_OTEL_ENDPOINT={otel_endpoint}" if otel_endpoint else \
                "# OSEYE_OTEL_ENDPOINT=localhost:4317"
    ti_misp = f"OSEYE_MISP_URL={misp_url}\nOSEYE_MISP_API_KEY={misp_key}" if misp_url else \
              "OSEYE_MISP_URL=\nOSEYE_MISP_API_KEY="

    # DB line in server.env: SQLite URL has no password so it's safe there;
    # PostgreSQL URL contains the password so it goes only in secrets.env.
    if db_backend == "sqlite":
        db_url_line = f"OSEYE_DB_URL={db_url}"
        db_url_secret = ""
    else:
        db_url_line = "# OSEYE_DB_URL is in secrets.env (contains password)"
        db_url_secret = f"\n# Database URL (contains password — keep in this file only)\nOSEYE_DB_URL=postgresql+asyncpg://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}\n"

    server_env = dedent(f"""\
        # OSEye Server — Environment Configuration
        # Generated by setup-server.py

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
        # Generated by setup-server.py
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

    server_env_path  = Path("/etc/oseye/server.env")
    secrets_env_path = Path("/etc/oseye/secrets.env")

    _write_secure(server_env_path, server_env, 0o640)
    ok(f"Written {server_env_path}")

    _write_secure(secrets_env_path, secrets_env, 0o600)
    ok(f"Written {secrets_env_path} (mode 600)")

    # ── Enrollment token ──────────────────────────────────────────────────────
    token = generate_enrollment_token(Path("/etc/oseye/enrollment_tokens"))
    ok("Enrollment token generated")

    # ── Summary ───────────────────────────────────────────────────────────────
    width = 64
    print()
    print(c("┌" + "─" * (width - 2) + "┐", GREEN, BOLD))
    print(c(f"│{'  Setup complete':^{width - 2}}│", GREEN, BOLD))
    print(c("├" + "─" * (width - 2) + "┤", GREEN, BOLD))
    lines = [
        f"  Server    : {hostname}",
        f"  API       : https://{hostname}:{api_port}",
        f"  gRPC      : {hostname}:{grpc_port}",
        f"  DB        : {db_backend}",
        "",
        "  Enrollment token (valid 24 h):",
        f"  {token}",
        "",
        "  To enroll an agent, run on the agent host:",
        f"    OSEYE_SERVER={hostname}:{api_port} \\",
        f"    OSEYE_TOKEN={token} \\",
        "    sudo bash enroll-agent.sh",
        "",
        "  Next: start the server stack:",
        "    docker compose -f infra/docker/docker-compose.prod.yml up -d",
    ]
    for line in lines:
        print(c(f"│ {line:<{width - 3}}│", GREEN))
    print(c("└" + "─" * (width - 2) + "┘", GREEN, BOLD))
    print()


if __name__ == "__main__":
    main()
