"""Shared PKI + filesystem helpers for the oseye-server CLI."""

from __future__ import annotations

import ipaddress
import os
import subprocess
from pathlib import Path

DIR_MODES: dict[str, int] = {
    "/etc/oseye/certs":             0o700,
    "/etc/oseye/enrollment_tokens": 0o700,
    "/etc/oseye/agent_keys":        0o700,
    "/etc/oseye/plugins":           0o750,
    "/etc/oseye/plugin_keys":       0o700,
    "/var/lib/oseye":               0o750,
    "/var/run/oseye":               0o755,
}


def run_openssl(cmd: list[str]) -> None:
    """Run an openssl command, raising RuntimeError with its stderr on failure."""
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(
            f"openssl failed (exit {result.returncode}): {stderr or '(no output)'}"
        )


def write_secure(path: Path, content: str, mode: int) -> None:
    """Create or overwrite a file with the exact mode from the first open() — no TOCTOU.

    Note: os.open() applies the umask to the mode. Call this outside any umask(0o077)
    block when writing files that need group-read bits (e.g. mode 0o640).
    """
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(content)


def create_dirs(extra: dict[str, int] | None = None) -> list[str]:
    dirs = dict(DIR_MODES)
    if extra:
        dirs.update(extra)
    created = []
    # umask(0) so that mkdir gets the exact requested mode for every directory,
    # including parents created by parents=True.
    old_umask = os.umask(0)
    try:
        for d, mode in dirs.items():
            p = Path(d)
            if not p.exists():
                p.mkdir(mode=mode, parents=True, exist_ok=True)
                created.append(d)
    finally:
        os.umask(old_umask)
    return created


_PKI_FILES = [
    "ca.key", "ca.crt",
    "server.crt", "server.key",
    "jwt_private.pem", "jwt_public.pem",
]


def generate_pki(certs_dir: Path, hostname: str, ip: str, *, force: bool = False) -> bool:
    """Generate CA + server cert + JWT keys. Returns True if generated, False if skipped.

    Atomicity: if any step fails, all partially-created PKI files are removed before
    the exception propagates so callers never encounter a half-built PKI.
    """
    if "/" in hostname or " " in hostname:
        raise ValueError(f"Invalid hostname {hostname!r}: must not contain '/' or spaces")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address {ip!r}")

    # Require ALL expected files to be present before skipping generation.
    all_present = all((certs_dir / f).exists() for f in _PKI_FILES)
    if all_present and not force:
        return False

    san_file = certs_dir / "san.tmp"
    old_umask = os.umask(0o077)
    try:
        try:
            run_openssl(["openssl", "genrsa", "-out", str(certs_dir / "ca.key"), "4096"])
            run_openssl(["openssl", "req", "-new", "-x509", "-days", "3650",
                         "-key", str(certs_dir / "ca.key"),
                         "-out", str(certs_dir / "ca.crt"),
                         "-subj", "/CN=OSEye-CA/O=OSEye/C=FR"])

            write_secure(san_file, f"subjectAltName=DNS:{hostname},DNS:localhost,IP:{ip},IP:127.0.0.1", 0o600)
            run_openssl(["openssl", "genrsa", "-out", str(certs_dir / "server.key"), "4096"])
            run_openssl(["openssl", "req", "-new",
                         "-key", str(certs_dir / "server.key"),
                         "-out", str(certs_dir / "server.csr"),
                         "-subj", f"/CN={hostname}/O=OSEye/C=FR"])
            try:
                run_openssl(["openssl", "x509", "-req", "-days", "825",
                             "-in", str(certs_dir / "server.csr"),
                             "-CA", str(certs_dir / "ca.crt"),
                             "-CAkey", str(certs_dir / "ca.key"),
                             "-CAcreateserial",
                             "-out", str(certs_dir / "server.crt"),
                             "-extfile", str(san_file)])
            finally:
                san_file.unlink(missing_ok=True)
                (certs_dir / "server.csr").unlink(missing_ok=True)

            run_openssl(["openssl", "genrsa", "-out", str(certs_dir / "jwt_private.pem"), "4096"])
            run_openssl(["openssl", "rsa", "-in", str(certs_dir / "jwt_private.pem"),
                         "-pubout", "-out", str(certs_dir / "jwt_public.pem")])
        except Exception:
            # Remove all partially-created PKI files to avoid a corrupted state.
            for fname in _PKI_FILES:
                (certs_dir / fname).unlink(missing_ok=True)
            raise
    finally:
        os.umask(old_umask)
    return True
