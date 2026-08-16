"""JWT handler — RS256 (production) and HS256 (test/dev) modes.

RS256 is used when private_key_path / public_key_path are supplied.
HS256 is used when the optional `secret` parameter is provided instead
(useful for unit tests that have no PEM files on disk).
"""

from __future__ import annotations

import json
import os
import pathlib
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from fastapi import HTTPException, status

from oseye.core.observability import get_logger

_logger = get_logger(__name__)

_data_dir = pathlib.Path(os.environ.get("OSEYE_DATA_DIR", "/var/lib/oseye"))
_BLOCKLIST_FILE = _data_dir / "revoked_tokens.json"


class JWTHandler:
    """Creates and verifies JWT tokens for OSEye API authentication.

    SEC-JWT-001: tokens include a ``jti`` claim (JWT ID). Revoked JTIs are
    tracked in an in-memory set with automatic expiry so the blocklist stays
    bounded. On logout or explicit revocation, call ``revoke_token(token)``.
    """

    def __init__(
        self,
        private_key_path: str,
        public_key_path: str,
        expire_minutes: int,
        *,
        secret: str | None = None,
    ) -> None:
        self._expire_minutes = expire_minutes
        if secret is not None:
            # HS256 mode — for unit tests without PEM files
            # API-08: enforce minimum key length to prevent weak secrets.
            if len(secret) < 32:
                raise ValueError("HS256 secret must be at least 32 bytes")
            self._algorithm = "HS256"
            self._sign_key: Any = secret
            self._verify_key: Any = secret
        else:
            self._algorithm = "RS256"
            self._sign_key = Path(private_key_path).read_text()
            self._verify_key = Path(public_key_path).read_text()

        # SEC-JWT-001: jti blocklist — {jti: expiry_timestamp_utc}
        # Bounded: revoked entries are pruned on every verify call once expired.
        # B-05: persisted to disk so the blocklist survives restarts.
        _data_dir.mkdir(parents=True, exist_ok=True)
        # TOCTOU fix: open the fd first, then fchmod on the fd to eliminate the
        # exists() → chmod() race window where the file could be replaced.
        try:
            _bl_fd = os.open(str(_BLOCKLIST_FILE), os.O_RDONLY)
            try:
                os.fchmod(_bl_fd, 0o600)
            finally:
                os.close(_bl_fd)
        except OSError:
            pass
        self._revoked_lock = threading.Lock()
        self._revoked: dict[str, datetime] = self._load_blocklist()

    # ------------------------------------------------------------------
    # Token creation
    # ------------------------------------------------------------------

    def create_token(self, subject: str, roles: list[str]) -> str:
        """Generate a signed JWT with sub, roles, jti, exp, iat."""
        now = datetime.now(tz=UTC)
        exp = now + timedelta(minutes=self._expire_minutes)
        payload: dict[str, Any] = {
            "sub": subject,
            "roles": roles,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": exp,
        }
        return jwt.encode(payload, self._sign_key, algorithm=self._algorithm)

    # ------------------------------------------------------------------
    # Token verification
    # ------------------------------------------------------------------

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify and decode a JWT.

        Raises HTTPException 401 if the token is invalid, expired, or revoked.
        """
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                self._verify_key,
                algorithms=[self._algorithm],
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as exc:
            _logger.warning("jwt_invalid", error=str(exc))
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # B-11: tokens without jti cannot be checked for revocation — reject them.
        jti: str | None = payload.get("jti")
        if jti is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # SEC-JWT-001: check and prune blocklist
        self._prune_revoked()
        with self._revoked_lock:
            if jti in self._revoked:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        return payload

    # ------------------------------------------------------------------
    # Token revocation
    # ------------------------------------------------------------------

    def revoke_token(self, token: str) -> None:
        """Add a token's jti to the blocklist until its natural expiry.

        Safe to call on an already-expired or already-revoked token.
        """
        try:
            # decode without verification — we only need the jti and exp claims
            payload: dict[str, Any] = jwt.decode(
                token,
                self._verify_key,
                algorithms=[self._algorithm],
                options={"verify_exp": False},
            )
        except jwt.InvalidTokenError as exc:
            _logger.warning("jwt_revoke_decode_failed", error=str(exc))
            return

        jti: str | None = payload.get("jti")
        if jti is None:
            return

        exp_raw = payload.get("exp")
        if isinstance(exp_raw, (int, float)):
            exp_dt = datetime.fromtimestamp(float(exp_raw), tz=UTC)
        else:
            # No exp — keep in blocklist for the default token lifetime
            exp_dt = datetime.now(tz=UTC) + timedelta(minutes=self._expire_minutes)

        with self._revoked_lock:
            self._revoked[jti] = exp_dt
        self._save_blocklist()
        _logger.info("jwt_revoked", jti=jti)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune_revoked(self) -> None:
        """Remove expired entries from the blocklist (called on each verify)."""
        now = datetime.now(tz=UTC)
        with self._revoked_lock:
            expired = [jti for jti, exp in self._revoked.items() if exp <= now]
            for jti in expired:
                del self._revoked[jti]
        if expired:
            self._save_blocklist()

    def _load_blocklist(self) -> dict[str, datetime]:
        """Load the blocklist from disk. Returns an empty dict if the file does not exist.

        B-05: format on disk is {jti: expiry_iso_string}.

        H-02: if the file exists but is unreadable or corrupted, log the error and
        raise RuntimeError (fail-closed) so that a corrupted blocklist cannot silently
        open the gate for revoked tokens. Set OSEYE_INSECURE=true to bypass (recovery
        only — never use in production).
        """
        if not _BLOCKLIST_FILE.exists():
            return {}
        try:
            raw: dict[str, str] = json.loads(_BLOCKLIST_FILE.read_text())
            result: dict[str, datetime] = {}
            for jti, expiry_str in raw.items():
                try:
                    result[jti] = datetime.fromisoformat(expiry_str)
                except (ValueError, TypeError):
                    pass
            return result
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "jwt_blocklist_load_failed",
                error=str(exc),
                path=str(_BLOCKLIST_FILE),
            )
            if os.environ.get("OSEYE_INSECURE", "").lower() == "true":
                _logger.warning(
                    "jwt_blocklist_bypassed_insecure",
                    path=str(_BLOCKLIST_FILE),
                )
                return {}
            raise RuntimeError(
                f"Blocklist file {_BLOCKLIST_FILE} exists but could not be loaded: {exc}. "
                "Fix or remove the file, or set OSEYE_INSECURE=true to bypass "
                "(not recommended in production)."
            ) from exc

    def _save_blocklist(self) -> None:
        """Write the blocklist to disk atomically (write + rename).

        B-05: uses a .tmp file to avoid a partial write being read on crash.
        The tmp file is created with mode 0o600 via os.open so it is never
        world-readable, even transiently (eliminates the chmod race).
        Caller must NOT hold _revoked_lock (acquires it internally).
        """
        try:
            with self._revoked_lock:
                snapshot = {jti: exp.isoformat() for jti, exp in self._revoked.items()}
            tmp = _BLOCKLIST_FILE.with_suffix(".tmp")
            _data_dir.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(snapshot).encode())
            finally:
                os.close(fd)
            tmp.rename(_BLOCKLIST_FILE)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("jwt_blocklist_save_failed", error=str(exc))
