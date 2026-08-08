"""SQL repository for API keys."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import ApiKeyRow


_HMAC_SECRET: bytes = os.getenv("OSEYE_SECRET_KEY", "dev-secret-key").encode()


def _hash_key(raw: str) -> str:
    # F4: HMAC-SHA256 with server secret instead of bare SHA-256
    return hmac.new(_HMAC_SECRET, raw.encode(), hashlib.sha256).hexdigest()


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
        if row is None or row.revoked:
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

    async def list(self) -> list[dict[str, object]]:
        async with self._session_factory() as session:
            rows = (await session.execute(select(ApiKeyRow))).scalars().all()
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
