"""oseye-server init — create system directories and generate PKI."""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

from ._pki import create_dirs, generate_pki, write_secure
from ._ui import BOLD, DIM, GREEN, c, err, header, ok, warn


def run(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="oseye-server init",
        description="Create system directories and generate PKI (non-interactive).",
    )
    parser.add_argument("--certs-dir", default="/etc/oseye/certs", metavar="PATH")
    parser.add_argument("--token-dir", default="/etc/oseye/enrollment_tokens", metavar="PATH")
    parser.add_argument("--hostname", default="", metavar="HOST",
                        help="Override auto-detected server hostname")
    parser.add_argument("--ip", default="", metavar="IP",
                        help="Override auto-detected server IP")
    parser.add_argument("--force", action="store_true",
                        help="Re-generate PKI even if already present")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        err("Must be run as root (sudo oseye-server init)")
        sys.exit(1)
    if subprocess.run(["openssl", "version"], capture_output=True).returncode != 0:
        err("openssl not found in PATH")
        sys.exit(1)

    header("OSEye Server — Initialize")

    hostname = args.hostname or (
        subprocess.run(["hostname", "-f"], capture_output=True, text=True).stdout.strip()
        or socket.gethostname()
    )
    ip_out = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.strip()
    ip = args.ip or (ip_out.split()[0] if ip_out else "127.0.0.1")

    print(c(f"  Hostname : {hostname}", DIM))
    print(c(f"  IP       : {ip}", DIM))

    created = create_dirs()
    for d in created:
        ok(f"Created {d}")
    if not created:
        ok("Directories already present")

    certs_dir = Path(args.certs_dir)
    print(c("  Generating PKI (this takes a moment)...", DIM))
    try:
        generated = generate_pki(certs_dir, hostname, ip, force=args.force)
    except ValueError as exc:
        err(str(exc))
        sys.exit(1)

    if generated:
        ok("CA generated (4096-bit, 10 years)")
        ok("Server certificate generated (4096-bit, 825 days)")
        ok("JWT RS256 key pair generated (4096-bit)")
    else:
        warn("PKI already present — skipped (use --force to regenerate)")

    token = secrets.token_hex(32)
    token_dir = Path(args.token_dir)
    token_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_secure(token_dir / token, str(int(time.time())), 0o600)
    ok("Enrollment token generated")

    width = 64
    lines = [
        f"  Certs : {args.certs_dir}/",
        f"  Host  : {hostname}",
        "",
        "  Enrollment token (valid 24 h):",
        f"  {token}",
        "",
        "  To enroll an agent:",
        "    oseye-config enroll --server <host>:<api-port> --token " + token,
        "",
        "  Next: oseye-server setup",
    ]
    print()
    print(c("┌" + "─" * (width - 2) + "┐", GREEN, BOLD))
    print(c(f"│{'  Initialization complete':^{width - 2}}│", GREEN, BOLD))
    print(c("├" + "─" * (width - 2) + "┤", GREEN, BOLD))
    for line in lines:
        print(c(f"│ {line:<{width - 3}}│", GREEN))
    print(c("└" + "─" * (width - 2) + "┘", GREEN, BOLD))
    print()
