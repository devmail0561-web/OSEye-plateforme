"""Unit tests for EnrollmentStore and enrollment API endpoints."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from oseye.enrollment_store import EnrollmentStore, _is_safe_token


# ---------------------------------------------------------------------------
# Fixtures — mini PKI for tests
# ---------------------------------------------------------------------------


def _generate_ca(tmp_path: Path) -> tuple[Path, Path]:
    """Generate a test CA cert and key, return (cert_path, key_path)."""
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "ca.key"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
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


def _make_store(tmp_path: Path) -> EnrollmentStore:
    ca_cert, ca_key = _generate_ca(tmp_path)
    token_dir = tmp_path / "tokens"
    token_dir.mkdir()
    settings = MagicMock()
    settings.enrollment_token_dir = str(token_dir)
    settings.tls_ca_cert_file = str(ca_cert)
    settings.tls_ca_key_file = str(ca_key)
    return EnrollmentStore(settings)


def _make_csr(hostname: str) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .sign(key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------
# Token management tests
# ---------------------------------------------------------------------------


def test_create_token(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    token = store.create_token()
    assert len(token) == 64
    assert all(c in "0123456789abcdef" for c in token)
    token_file = Path(store._token_dir) / token
    assert token_file.exists()


def test_validate_token_valid(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    token = store.create_token()
    assert store.validate_token(token) is True


def test_validate_token_expired(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    token = store.create_token()
    # Backdate the token file
    token_file = Path(store._token_dir) / token
    token_file.write_text(str(time.time() - 90_001))
    assert store.validate_token(token) is False


def test_validate_token_unknown(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    assert store.validate_token("a" * 64) is False


def test_validate_token_path_traversal(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    assert store.validate_token("../etc/passwd") is False
    assert store.validate_token("../../secrets") is False


def test_consume_token(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    token = store.create_token()
    assert store.validate_token(token) is True
    store.consume_token(token)
    assert store.validate_token(token) is False
    token_file = Path(store._token_dir) / token
    assert not token_file.exists()


def test_consume_token_idempotent(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    token = store.create_token()
    store.consume_token(token)
    store.consume_token(token)  # must not raise


# ---------------------------------------------------------------------------
# Certificate operations tests
# ---------------------------------------------------------------------------


def test_get_ca_cert_pem(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    pem = store.get_ca_cert_pem()
    assert pem.startswith("-----BEGIN CERTIFICATE-----")


def test_sign_csr_valid(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    csr_pem = _make_csr("agent-test.local")
    cert_pem = store.sign_csr(csr_pem, "agent-test.local")
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    # Verify the cert is parseable
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert cn == "agent-test.local"


def test_sign_csr_rejects_invalid_csr(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    with pytest.raises(ValueError, match="Invalid CSR"):
        store.sign_csr("not-a-valid-pem", "host.local")


def test_sign_csr_rejects_invalid_hostname(tmp_path: Path) -> None:
    store = _make_store(tmp_path)
    csr_pem = _make_csr("host")
    with pytest.raises(ValueError, match="Invalid hostname"):
        store.sign_csr(csr_pem, "../etc/passwd")


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def app_with_store(tmp_path: Path):
    """Return a TestClient with EnrollmentStore wired on app.state."""
    from fastapi.testclient import TestClient

    from oseye.api.app import create_app
    from oseye.config import Settings

    settings = Settings(  # type: ignore[call-arg]
        db_url="sqlite+aiosqlite:///:memory:",
        jwt_private_key_path="/nonexistent",
        jwt_public_key_path="/nonexistent",
    )
    app = create_app(settings)
    store = _make_store(tmp_path)
    app.state.enrollment_store = store
    return TestClient(app, raise_server_exceptions=True), store


def test_api_get_ca_cert_valid_token(app_with_store) -> None:
    client, store = app_with_store
    token = store.create_token()
    resp = client.get(
        "/api/v1/enroll/ca",
        headers={"X-Enrollment-Token": token},
    )
    assert resp.status_code == 200
    assert "BEGIN CERTIFICATE" in resp.text
    # Token must still be valid after GET (not consumed)
    assert store.validate_token(token) is True


def test_api_get_ca_cert_invalid_token(app_with_store) -> None:
    client, _ = app_with_store
    resp = client.get(
        "/api/v1/enroll/ca",
        headers={"X-Enrollment-Token": "b" * 64},
    )
    assert resp.status_code == 404


def test_api_post_csr_valid(app_with_store) -> None:
    client, store = app_with_store
    token = store.create_token()
    csr_pem = _make_csr("myhost.local")
    resp = client.post(
        "/api/v1/enroll/sign",
        json={"csr": csr_pem, "hostname": "myhost.local"},
        headers={"X-Enrollment-Token": token},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "cert" in data
    assert "BEGIN CERTIFICATE" in data["cert"]


def test_api_post_csr_invalid_token(app_with_store) -> None:
    client, _ = app_with_store
    csr_pem = _make_csr("myhost.local")
    resp = client.post(
        "/api/v1/enroll/sign",
        json={"csr": csr_pem, "hostname": "myhost.local"},
        headers={"X-Enrollment-Token": "c" * 64},
    )
    assert resp.status_code == 404


def test_api_post_csr_one_time_use(app_with_store) -> None:
    client, store = app_with_store
    token = store.create_token()
    csr_pem = _make_csr("myhost.local")
    payload = {"csr": csr_pem, "hostname": "myhost.local"}
    headers = {"X-Enrollment-Token": token}
    resp1 = client.post("/api/v1/enroll/sign", json=payload, headers=headers)
    assert resp1.status_code == 200
    resp2 = client.post("/api/v1/enroll/sign", json=payload, headers=headers)
    assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


def test_is_safe_token_valid() -> None:
    assert _is_safe_token("a" * 64) is True
    assert _is_safe_token("0123456789abcdef" * 4) is True


def test_is_safe_token_invalid() -> None:
    assert _is_safe_token("../etc/passwd") is False
    assert _is_safe_token("A" * 64) is False  # uppercase not allowed
    assert _is_safe_token("a" * 63) is False  # too short
    assert _is_safe_token("a" * 65) is False  # too long
