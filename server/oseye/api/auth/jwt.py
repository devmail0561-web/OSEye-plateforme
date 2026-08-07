"""JWT handler — RS256 (production) and HS256 (test/dev) modes.

RS256 is used when private_key_path / public_key_path are supplied.
HS256 is used when the optional `secret` parameter is provided instead
(useful for unit tests that have no PEM files on disk).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from fastapi import HTTPException, status

from oseye.core.observability import get_logger

_logger = get_logger(__name__)


class JWTHandler:
    """Creates and verifies JWT tokens for OSEye API authentication."""

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
            self._algorithm = "HS256"
            self._sign_key: Any = secret
            self._verify_key: Any = secret
        else:
            self._algorithm = "RS256"
            self._sign_key = Path(private_key_path).read_text()
            self._verify_key = Path(public_key_path).read_text()

    def create_token(self, subject: str, roles: list[str]) -> str:
        """Generate a signed JWT with sub, roles, exp, iat."""
        now = datetime.now(tz=UTC)
        payload: dict[str, Any] = {
            "sub": subject,
            "roles": roles,
            "iat": now,
            "exp": now + timedelta(minutes=self._expire_minutes),
        }
        return jwt.encode(payload, self._sign_key, algorithm=self._algorithm)

    def verify_token(self, token: str) -> dict[str, Any]:
        """Verify and decode a JWT.

        Raises HTTPException 401 if the token is invalid or expired.
        """
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                self._verify_key,
                algorithms=[self._algorithm],
            )
            return payload
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
