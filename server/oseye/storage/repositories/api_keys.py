"""SQL repository for API keys."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import ApiKeyRow

_log_keys = logging.getLogger(__name__)


def _load_hmac_secret() -> bytes:
    """Load and validate OSEYE_SECRET_KEY from the environment.

    Raises RuntimeError if the variable is absent or too short (< 32 chars),
    so the process refuses to start with an insecure default.
    """
    raw = os.getenv("OSEYE_SECRET_KEY", "")
    if not raw:
        _log_keys.critical(
            "OSEYE_SECRET_KEY not set — refusing to start with insecure default"
        )
        raise RuntimeError(
            "OSEYE_SECRET_KEY environment variable is required. "
            "Set it to a random string of at least 32 characters."
        )
    if len(raw) < 32:
        raise RuntimeError(
            f"OSEYE_SECRET_KEY is too short ({len(raw)} chars). "
            "Minimum 32 characters required."
        )
    return raw.encode()


_HMAC_SECRET: bytes | None = None


def _get_hmac_secret() -> bytes:
    global _HMAC_SECRET  # noqa: PLW0603
    if _HMAC_SECRET is None:
        _HMAC_SECRET = _load_hmac_secret()
    return _HMAC_SECRET


def _hash_key(raw: str) -> str:
    return hmac.new(_get_hmac_secret(), raw.encode(), hashlib.sha256).hexdigest()


class SQLApiKeyRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    def generate(self) -> str:
        return "osk_" + secrets.token_urlsafe(32)

    async def create(
        self,
        name: str,
        roles: list[str],
        created_by: str,
        expires_at: datetime | None = None,
    ) -> tuple[str, str]:
        """Create a new API key. Returns (raw_key, key_id)."""
        raw = self.generate()
        key_id = str(uuid4())
        row = ApiKeyRow(
            key_id=key_id,
            key_hash=_hash_key(raw),
            name=name,
            roles=json.dumps(roles),
            created_at=datetime.now(UTC).isoformat(),
            expires_at=expires_at.isoformat() if expires_at else None,
            revoked=False,
            created_by=created_by,
        )
        async with self._session_factory() as session:
            async with session.begin():
                session.add(row)
        return raw, key_id

    async def verify(self, raw: str) -> dict[str, object] | None:
        """Return {key_id, name, roles} if the key is valid, else None."""
        h = _hash_key(raw)
        async with self._session_factory() as session:
            row = (
                await session.execute(select(ApiKeyRow).where(ApiKeyRow.key_hash == h))
            ).scalars().first()
        # L-20: also reject soft-deleted keys
        if row is None or row.revoked or row.deleted_at is not None:
            return None
        if row.expires_at and datetime.fromisoformat(row.expires_at) < datetime.now(UTC):
            return None
        return {
            "key_id": row.key_id,
            "name": row.name,
            "roles": json.loads(row.roles),
        }

    async def revoke(self, key_id: str) -> bool:
        """Revoke by key_id. Returns True if found."""
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(ApiKeyRow, key_id)
                if row is None:
                    return False
                row.revoked = True
        return True

    async def delete(self, key_id: str) -> bool:
        """Soft-delete a key by recording deleted_at; the row is retained for audit.

        L-20: physical DELETE replaced by soft-delete so the key identity, name,
        and creator are preserved in the audit trail. verify() and list() already
        filter out rows where deleted_at IS NOT NULL.
        Requires migration: ALTER TABLE api_keys ADD COLUMN deleted_at VARCHAR(64) NULL
        """
        now = datetime.now(UTC).isoformat()
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(ApiKeyRow, key_id)
                if row is None:
                    return False
                _log_keys.info(
                    "api_key.soft_delete key_id=%s name=%r created_by=%r",
                    key_id, row.name, row.created_by,
                )
                row.deleted_at = now
        return True

    async def list(self, include_revoked: bool = False) -> list[dict[str, object]]:
        async with self._session_factory() as session:
            stmt = select(ApiKeyRow)
            if not include_revoked:
                stmt = stmt.where(ApiKeyRow.revoked == False)  # noqa: E712
            # L-20: always hide soft-deleted keys from listings
            stmt = stmt.where(ApiKeyRow.deleted_at == None)  # noqa: E711
            rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "key_id": r.key_id,
                "name": r.name,
                "roles": json.loads(r.roles),
                "created_at": r.created_at,
                "expires_at": r.expires_at,
                "revoked": r.revoked,
                "created_by": r.created_by,
            }
            for r in rows
        ]
