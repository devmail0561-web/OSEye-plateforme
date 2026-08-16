"""Enrollment token store and agent certificate signing.

Tokens are persisted as files in enrollment_token_dir (one file per token,
content = Unix timestamp of creation). They are one-time-use and expire after
TOKEN_TTL_SECONDS (24 hours).

The sign_csr() method signs an agent CSR with the server CA key and returns
a PEM-encoded certificate.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oseye.config import Settings

TOKEN_TTL_SECONDS = 86_400  # 24 hours
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")


class EnrollmentStore:
    """Manages enrollment tokens and agent certificate signing."""

    def __init__(self, settings: Settings) -> None:
        self._token_dir = Path(settings.enrollment_token_dir)
        self._ca_cert_path = Path(settings.tls_ca_cert_file)
        self._ca_key_path = Path(settings.tls_ca_key_file)
        _pw = settings.tls_ca_key_password.get_secret_value()
        self._ca_key_password: bytes | None = _pw.encode() if _pw else None
        self._token_dir.mkdir(parents=True, exist_ok=True)
        # NE-R-05: serialises validate+consume under a lock to prevent TOCTOU races.
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def create_token(self) -> str:
        """Generate a new enrollment token (hex-64) and persist it."""
        token = secrets.token_hex(32)
        token_file = self._token_dir / token
        token_file.write_text(str(time.time()))
        token_file.chmod(0o600)
        return token

    def validate_token(self, token: str) -> bool:
        """Return True if the token exists and has not expired."""
        if not _is_safe_token(token):
            return False
        token_file = self._token_dir / token
        if not token_file.exists():
            return False
        try:
            created_at = float(token_file.read_text().strip())
        except (ValueError, OSError):
            return False
        return (time.time() - created_at) < TOKEN_TTL_SECONDS

    def consume_token(self, token: str) -> None:
        """Delete the token file (one-time use)."""
        token_file = self._token_dir / token
        try:
            token_file.unlink()
        except FileNotFoundError:
            pass

    def validate_and_consume(self, token: str) -> bool:
        """Atomically validate and consume *token* under a lock.

        NE-R-05: combining validate + consume under a single lock prevents the
        TOCTOU window where two concurrent requests both pass validate_token
        before either calls consume_token.

        Returns True if the token was valid and has been consumed.
        Returns False if the token was absent, expired, or already consumed.
        """
        with self._lock:
            if not self.validate_token(token):
                return False
            self.consume_token(token)
            return True

    # ------------------------------------------------------------------
    # Certificate operations
    # ------------------------------------------------------------------

    def get_ca_cert_pem(self) -> str:
        """Return the CA certificate as a PEM string."""
        return self._ca_cert_path.read_text()

    def sign_csr(self, csr_pem: str, hostname: str) -> str:
        """Sign an agent CSR with the CA key and return a PEM certificate.

        Consumes the token is NOT done here — caller (router) is responsible
        for consuming the token after this call succeeds.

        Raises ValueError on invalid CSR or hostname.
        """
        if not _HOSTNAME_RE.match(hostname):
            raise ValueError(f"Invalid hostname: {hostname!r}")

        # Parse and validate CSR
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except Exception as exc:
            raise ValueError(f"Invalid CSR: {exc}") from exc
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")

        # Load CA cert and key.
        # Set OSEYE_TLS_CA_KEY_PASSWORD to decrypt a passphrase-protected CA key.
        ca_cert = x509.load_pem_x509_certificate(self._ca_cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(
            self._ca_key_path.read_bytes(), password=self._ca_key_password
        )
        if not isinstance(ca_key, rsa.RSAPrivateKey):
            raise ValueError("CA key must be an RSA private key")

        import datetime

        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
            )
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()


def _is_safe_token(token: str) -> bool:
    """Reject tokens that could be used for path traversal."""
    return bool(re.fullmatch(r"[0-9a-f]{64}", token))
