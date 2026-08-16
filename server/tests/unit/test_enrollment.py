"""Unit tests for EnrollmentStore and enrollment API endpoints."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from oseye.enrollment_store import EnrollmentStore, _is_safe_token
from oseye.storage.migrations import run_migrations

os.environ.setdefault("OSEYE_SECRET_KEY", "test-secret-key-at-least-32-chars-long!!")


# ---------------------------------------------------------------------------
# Fixtures — mini PKI + async DB
# ---------------------------------------------------------------------------

def _generate_ca(tmp_path: Path) -> tuple[Path, Path]:
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "ca.key"
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test-CA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test-CA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "ca.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def _make_csr(hostname: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


@pytest_asyncio.fixture
async def store(tmp_path: Path):
    ca_cert, ca_key = _generate_ca(tmp_path)
    from unittest.mock import MagicMock
    settings = MagicMock()
    settings.tls_ca_cert_file = str(ca_cert)
    settings.tls_ca_key_file = str(ca_key)
    settings.tls_ca_key_password = SecretStr("")
    settings.enrollment_token_default_ttl_hours = 24

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)
    sf: async_sessionmaker[AsyncSession] = async_sessionmaker(
        bind=engine, expire_on_commit=False, class_=AsyncSession,
    )
    s = EnrollmentStore(settings, sf)
    yield s
    await engine.dispose()


# ---------------------------------------------------------------------------
# Token management
# ---------------------------------------------------------------------------

async def test_create_token(store: EnrollmentStore) -> None:
    raw, token_id = await store.create_token(created_by="admin")
    assert len(raw) == 64
    assert all(c in "0123456789abcdef" for c in raw)
    assert len(token_id) == 36  # UUID


async def test_validate_token_valid(store: EnrollmentStore) -> None:
    raw, _ = await store.create_token(created_by="admin")
    assert await store.validate_token(raw) is True


async def test_validate_token_unknown(store: EnrollmentStore) -> None:
    assert await store.validate_token("a" * 64) is False


async def test_validate_token_path_traversal(store: EnrollmentStore) -> None:
    assert await store.validate_token("../etc/passwd") is False


async def test_validate_and_consume(store: EnrollmentStore) -> None:
    raw, _ = await store.create_token(created_by="admin")
    assert await store.validate_and_consume(raw) is True
    assert await store.validate_token(raw) is False  # consumed


async def test_validate_and_consume_idempotent(store: EnrollmentStore) -> None:
    raw, _ = await store.create_token(created_by="admin")
    assert await store.validate_and_consume(raw) is True
    assert await store.validate_and_consume(raw) is False  # already gone


async def test_custom_ttl(store: EnrollmentStore) -> None:
    raw, token_id = await store.create_token(created_by="admin", ttl_hours=72)
    tokens = await store.list_tokens()
    match = next(t for t in tokens if t["token_id"] == token_id)
    from datetime import UTC, datetime, timedelta
    expires = datetime.fromisoformat(match["expires_at"])
    delta = expires - datetime.now(UTC)
    assert timedelta(hours=71) < delta < timedelta(hours=73)


async def test_list_tokens(store: EnrollmentStore) -> None:
    _, id1 = await store.create_token(created_by="admin")
    _, id2 = await store.create_token(created_by="admin")
    tokens = await store.list_tokens()
    ids = {t["token_id"] for t in tokens}
    assert {id1, id2}.issubset(ids)
    # Raw token values must not appear in listing
    for t in tokens:
        assert "token_hash" not in t
        assert "token" not in t


async def test_revoke_token(store: EnrollmentStore) -> None:
    raw, token_id = await store.create_token(created_by="admin")
    assert await store.revoke_token(token_id) is True
    assert await store.validate_token(raw) is False


async def test_revoke_token_not_found(store: EnrollmentStore) -> None:
    assert await store.revoke_token("00000000-0000-0000-0000-000000000000") is False


# ---------------------------------------------------------------------------
# Certificate operations (synchronous)
# ---------------------------------------------------------------------------

async def test_get_ca_cert_pem(store: EnrollmentStore) -> None:
    assert store.get_ca_cert_pem().startswith("-----BEGIN CERTIFICATE-----")


async def test_sign_csr_valid(store: EnrollmentStore) -> None:
    csr_pem = _make_csr("agent-test.local")
    cert_pem = store.sign_csr(csr_pem, "agent-test.local")
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "agent-test.local"


async def test_sign_csr_rejects_invalid_csr(store: EnrollmentStore) -> None:
    with pytest.raises(ValueError, match="Invalid CSR"):
        store.sign_csr("not-a-valid-pem", "host.local")


async def test_sign_csr_rejects_invalid_hostname(store: EnrollmentStore) -> None:
    csr_pem = _make_csr("host")
    with pytest.raises(ValueError, match="Invalid hostname"):
        store.sign_csr(csr_pem, "../etc/passwd")


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def api(tmp_path: Path):
    """FastAPI test app with EnrollmentStore and admin JWT wired."""
    from unittest.mock import MagicMock

    from oseye.api.app import create_app
    from oseye.api.auth.jwt import JWTHandler
    from oseye.config import Settings

    ca_cert, ca_key = _generate_ca(tmp_path)
    settings = Settings(  # type: ignore[call-arg]
        db_url="sqlite+aiosqlite:///:memory:",
        jwt_private_key_path="/dev/null",
        jwt_public_key_path="/dev/null",
    )
    app = create_app(settings)
    app.state.jwt_handler = JWTHandler(
        private_key_path="", public_key_path="",
        expire_minutes=15, secret="test-secret-32-chars-minimum-xxx",
    )

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    await run_migrations(engine)
    sf: async_sessionmaker[AsyncSession] = async_sessionmaker(
        bind=engine, expire_on_commit=False, class_=AsyncSession,
    )

    mock_settings = MagicMock()
    mock_settings.tls_ca_cert_file = str(ca_cert)
    mock_settings.tls_ca_key_file = str(ca_key)
    mock_settings.tls_ca_key_password = SecretStr("")
    mock_settings.enrollment_token_default_ttl_hours = 24

    app.state.enrollment_store = EnrollmentStore(mock_settings, sf)

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        yield client, app.state.enrollment_store

    await engine.dispose()


def _make_jwt() -> str:
    from oseye.api.auth.jwt import JWTHandler
    return JWTHandler(
        private_key_path="", public_key_path="",
        expire_minutes=15, secret="test-secret-32-chars-minimum-xxx",
    ).create_token(subject="admin", roles=["admin"])


async def test_api_create_token(api) -> None:
    client, _ = api
    jwt = _make_jwt()
    resp = await client.post(
        "/api/v1/enroll/tokens",
        json={},
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert len(data["token"]) == 64
    assert "token_id" in data


async def test_api_create_token_custom_ttl(api) -> None:
    client, _ = api
    jwt = _make_jwt()
    resp = await client.post(
        "/api/v1/enroll/tokens",
        json={"expires_in_hours": 48},
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert resp.status_code == 201


async def test_api_get_ca_cert_valid_token(api) -> None:
    client, store = api
    raw, _ = await store.create_token(created_by="admin")
    resp = await client.get(
        "/api/v1/enroll/ca",
        headers={"X-Enrollment-Token": raw},
    )
    assert resp.status_code == 200
    assert "BEGIN CERTIFICATE" in resp.text
    assert await store.validate_token(raw) is True  # not consumed


async def test_api_get_ca_cert_invalid_token(api) -> None:
    client, _ = api
    resp = await client.get(
        "/api/v1/enroll/ca",
        headers={"X-Enrollment-Token": "b" * 64},
    )
    assert resp.status_code == 404


async def test_api_sign_csr_valid(api) -> None:
    client, store = api
    raw, _ = await store.create_token(created_by="admin")
    csr_pem = _make_csr("myhost.local")
    resp = await client.post(
        "/api/v1/enroll/sign",
        json={"csr": csr_pem, "hostname": "myhost.local"},
        headers={"X-Enrollment-Token": raw},
    )
    assert resp.status_code == 200
    assert "BEGIN CERTIFICATE" in resp.json()["cert"]


async def test_api_sign_csr_one_time_use(api) -> None:
    client, store = api
    raw, _ = await store.create_token(created_by="admin")
    csr_pem = _make_csr("myhost.local")
    payload = {"csr": csr_pem, "hostname": "myhost.local"}
    headers = {"X-Enrollment-Token": raw}
    r1 = await client.post("/api/v1/enroll/sign", json=payload, headers=headers)
    assert r1.status_code == 200
    r2 = await client.post("/api/v1/enroll/sign", json=payload, headers=headers)
    assert r2.status_code == 404


async def test_api_revoke_token(api) -> None:
    client, store = api
    jwt = _make_jwt()
    raw, token_id = await store.create_token(created_by="admin")
    resp = await client.delete(
        f"/api/v1/enroll/tokens/{token_id}",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert resp.status_code == 204
    assert await store.validate_token(raw) is False


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------

def test_is_safe_token_valid() -> None:
    assert _is_safe_token("a" * 64) is True
    assert _is_safe_token("0123456789abcdef" * 4) is True


def test_is_safe_token_invalid() -> None:
    assert _is_safe_token("../etc/passwd") is False
    assert _is_safe_token("A" * 64) is False
    assert _is_safe_token("a" * 63) is False
    assert _is_safe_token("a" * 65) is False
