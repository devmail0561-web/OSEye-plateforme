"""Enrollment token store and agent certificate signing.

Tokens are stored in the database (enrollment_tokens table) as HMAC-SHA256
hashes — the raw token value is never persisted. TTL is configurable per
token at creation time (default: OSEYE_ENROLLMENT_TOKEN_DEFAULT_TTL_HOURS).

The sign_csr() method signs an agent CSR with the server CA key and returns
a PEM-encoded certificate.
"""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.config import Settings
from oseye.storage.repositories.enrollment_tokens import SQLEnrollmentTokenRepository

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")


class EnrollmentStore:
    """Manages enrollment tokens (DB-backed) and agent certificate signing."""

    def __init__(
        self,
        settings: Settings,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._settings = settings
        self._ca_cert_path = Path(settings.tls_ca_cert_file)
        _pw = settings.tls_ca_key_password.get_secret_value()
        _ca_key_password: bytes | None = _pw.encode() if _pw else None
        self._default_ttl_hours = settings.enrollment_token_default_ttl_hours
        self._repo = SQLEnrollmentTokenRepository(session_factory)
        # Fix 7: parse CA key once at startup — avoids disk I/O + decryption on every sign_csr.
        self._ca_key = serialization.load_pem_private_key(
            Path(settings.tls_ca_key_file).read_bytes(), password=_ca_key_password
        )
        # Cache CA cert to avoid re-reading on every sign_csr() call (audit L note).
        self._ca_cert = x509.load_pem_x509_certificate(self._ca_cert_path.read_bytes())

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    async def create_token(
        self,
        created_by: str,
        ttl_hours: int | None = None,
    ) -> tuple[str, str]:
        """Generate a token, persist its hash. Returns (raw_token, token_id).

        ttl_hours overrides the server default. The raw token is shown once
        to the caller and never stored.
        """
        ttl = ttl_hours if ttl_hours is not None else self._default_ttl_hours
        raw = secrets.token_hex(32)
        expires_at = datetime.now(UTC) + timedelta(hours=ttl)
        token_id = await self._repo.create(raw, expires_at, created_by)
        return raw, token_id

    async def validate_token(self, raw_token: str) -> bool:
        """Return True if the token exists and has not expired."""
        if not _is_safe_token(raw_token):
            return False
        return await self._repo.verify(raw_token)

    async def validate_and_consume(self, raw_token: str) -> bool:
        """Atomically validate and delete the token (one-time use).

        NE-R-05: the DELETE is atomic at the DB level — no TOCTOU race.
        """
        if not _is_safe_token(raw_token):
            return False
        return await self._repo.verify_and_consume(raw_token)

    async def list_tokens(self) -> list[dict]:
        """Return active (non-expired) tokens. Raw values never included."""
        return await self._repo.list_active()

    async def revoke_token(self, token_id: str) -> bool:
        """Delete a token by token_id. Returns True if it existed."""
        return await self._repo.revoke(token_id)

    # ------------------------------------------------------------------
    # Certificate operations
    # ------------------------------------------------------------------

    def get_ca_cert_pem(self) -> str:
        """Return the CA certificate as a PEM string."""
        return self._ca_cert_path.read_text()

    def sign_csr(self, csr_pem: str, hostname: str) -> str:
        """Sign an agent CSR with the CA key and return a PEM certificate.

        Raises ValueError on invalid CSR or hostname.
        """
        if not _HOSTNAME_RE.match(hostname):
            raise ValueError(f"Invalid hostname: {hostname!r}")

        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except Exception as exc:
            raise ValueError(f"Invalid CSR: {exc}") from exc
        if not csr.is_signature_valid:
            raise ValueError("CSR signature is invalid")

        ca_cert = self._ca_cert
        if not isinstance(self._ca_key, rsa.RSAPrivateKey):
            raise ValueError("CA key must be an RSA private key")
        ca_key = self._ca_key

        import datetime as dt
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=365))
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
    """Reject tokens that could be used for injection."""
    return bool(re.fullmatch(r"[0-9a-f]{64}", token))
