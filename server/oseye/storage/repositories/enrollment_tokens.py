"""SQL repository for enrollment tokens."""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import delete as sql_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import EnrollmentTokenRow
from oseye.storage.repositories.api_keys import _get_hmac_secret

# Fix 4: domain prefix prevents hash collision with API keys sharing the same secret.
_DOMAIN = b"enroll:"


def _hash_token(raw: str) -> str:
    return hmac.new(_get_hmac_secret(), _DOMAIN + raw.encode(), hashlib.sha256).hexdigest()


class SQLEnrollmentTokenRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(
        self,
        raw_token: str,
        expires_at: datetime,
        created_by: str,
    ) -> str:
        """Persist a hashed token. Returns token_id (UUID)."""
        token_id = str(uuid4())
        row = EnrollmentTokenRow(
            token_id=token_id,
            token_hash=_hash_token(raw_token),
            # Fix 3: store with explicit UTC offset so string comparison is consistent.
            created_at=datetime.now(UTC).isoformat(),
            expires_at=expires_at.astimezone(UTC).isoformat(),
            created_by=created_by,
        )
        async with self._session_factory() as session:
            async with session.begin():
                session.add(row)
        return token_id

    async def verify_and_consume(self, raw_token: str) -> bool:
        """Atomically validate and delete the token. Returns True if valid.

        Fix 1: single DELETE … WHERE eliminates the SELECT+delete TOCTOU race.
        Two concurrent requests with the same token can only both DELETE; exactly
        one will see rowcount == 1 and proceed — the other gets rowcount == 0.

        Fix 3: string comparison is safe here because all expires_at values are
        stored via .astimezone(UTC).isoformat() → consistent YYYY-MM-DDTHH:MM:SS…+00:00
        format, which sorts correctly lexicographically.
        """
        h = _hash_token(raw_token)
        now = datetime.now(UTC).isoformat()
        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    sql_delete(EnrollmentTokenRow)
                    .where(EnrollmentTokenRow.token_hash == h)
                    .where(EnrollmentTokenRow.expires_at > now)
                )
        return result.rowcount == 1

    async def verify(self, raw_token: str) -> bool:
        """Validate without consuming (used by GET /enroll/ca)."""
        h = _hash_token(raw_token)
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(EnrollmentTokenRow).where(EnrollmentTokenRow.token_hash == h)
                )
            ).scalars().first()
        if row is None:
            return False
        # Fix 3: Python-side comparison with timezone-aware datetime.
        return datetime.fromisoformat(row.expires_at) >= datetime.now(UTC)

    async def revoke(self, token_id: str) -> bool:
        """Delete a token by token_id. Returns True if it existed."""
        async with self._session_factory() as session:
            async with session.begin():
                result = await session.execute(
                    sql_delete(EnrollmentTokenRow).where(
                        EnrollmentTokenRow.token_id == token_id
                    )
                )
        return result.rowcount > 0

    async def list_active(self) -> list[dict]:
        """Return non-expired tokens (token_hash never included).

        Fix 3: expiry is compared Python-side (timezone-aware).
        Fix 8: expired rows are purged in the same transaction.
        """
        now = datetime.now(UTC)
        async with self._session_factory() as session:
            async with session.begin():
                rows = (
                    await session.execute(select(EnrollmentTokenRow))
                ).scalars().all()
                expired = [
                    r.token_id for r in rows
                    if datetime.fromisoformat(r.expires_at) < now
                ]
                if expired:
                    await session.execute(
                        sql_delete(EnrollmentTokenRow).where(
                            EnrollmentTokenRow.token_id.in_(expired)
                        )
                    )
        return [
            {
                "token_id":   r.token_id,
                "created_at": r.created_at,
                "expires_at": r.expires_at,
                "created_by": r.created_by,
            }
            for r in rows
            if datetime.fromisoformat(r.expires_at) >= now
        ]
