"""oseye-server validate — validate the server configuration."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


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

    import textwrap
    rows = [
        ("DB",        f"{s.db_backend} — {s.db_url[:60]}{'…' if len(s.db_url) > 60 else ''}"),
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
    for path in (s.tls_cert_file, s.tls_key_file, s.tls_ca_cert_file,
                 s.tls_ca_key_file, s.jwt_private_key_path, s.jwt_public_key_path):
        if not Path(path).exists():
            missing_files.append(path)

    col = max(len(k) for k, _ in rows)
    for key, val in rows:
        print(f"  {key:<{col}}  {val}")

    if missing_files:
        print()
        print("  Missing files:", file=sys.stderr)
        for f in missing_files:
            print(f"    ✗ {f}", file=sys.stderr)
        sys.exit(1)
