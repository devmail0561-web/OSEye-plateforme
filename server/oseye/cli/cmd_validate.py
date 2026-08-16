"""oseye-server validate — validate the server configuration."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse


def _mask_db_url(url: str) -> str:
    """Replace the password component of a DB URL with ***."""
    try:
        p = urlparse(url)
        if p.password:
            masked = p._replace(netloc=p.netloc.replace(f":{p.password}@", ":***@", 1))
            return urlunparse(masked)[:60]
    except Exception:
        pass
    return url[:60]


def _check_cert(path: str) -> str | None:
    """Return a warning string if the cert is expired or unreadable, else None."""
    try:
        from cryptography import x509 as _x509
        data = Path(path).read_bytes()
        cert = _x509.load_pem_x509_certificate(data)
        if cert.not_valid_after_utc < datetime.now(UTC):
            return f"EXPIRED (expired {cert.not_valid_after_utc.date()})"
    except Exception as exc:
        return f"unreadable ({exc})"
    return None


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server validate",
        description="Load and validate the server configuration.",
    )
    parser.parse_args(argv)

    try:
        from oseye.config import Settings
        s = Settings()
    except Exception as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        sys.exit(1)

    print("OK — configuration is valid")
    print()

    rows = [
        ("DB",        f"{s.db_backend} — {_mask_db_url(s.db_url)}"),
        ("Redis",     s.redis_url),
        ("API",       f"{s.api_host}:{s.api_port}"),
        ("gRPC",      f":{s.grpc_port}"),
        ("TLS cert",  s.tls_cert_file),
        ("CA cert",   s.tls_ca_cert_file),
        ("JWT priv",  s.jwt_private_key_path),
        ("Profile",   s.default_surveillance_profile),
        ("Log level", s.log_level),
    ]

    missing_files: list[str] = []
    cert_warnings: list[str] = []
    cert_paths = (s.tls_cert_file, s.tls_ca_cert_file)
    for path in (s.tls_cert_file, s.tls_key_file, s.tls_ca_cert_file,
                 s.tls_ca_key_file, s.jwt_private_key_path, s.jwt_public_key_path):
        if not Path(path).exists():
            missing_files.append(path)
        elif path in cert_paths:
            warn = _check_cert(path)
            if warn:
                cert_warnings.append(f"{path}: {warn}")

    col = max(len(k) for k, _ in rows)
    for key, val in rows:
        print(f"  {key:<{col}}  {val}")

    if cert_warnings:
        print()
        for w in cert_warnings:
            print(f"  WARNING: {w}", file=sys.stderr)

    if missing_files:
        print()
        print("  Missing files:", file=sys.stderr)
        for f in missing_files:
            print(f"    ✗ {f}", file=sys.stderr)
        sys.exit(1)
