"""Repository for rule change log (P9 — versioning audit trail)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import RuleChangeLogRow


class SQLRuleChangeLogRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def record(
        self,
        rule_id: str,
        version: int,
        change_type: str,
        *,
        author: str | None = None,
        diff_json: str | None = None,
        yaml_snapshot: str | None = None,
    ) -> RuleChangeLogRow:
        row = RuleChangeLogRow(
            rule_id=rule_id,
            version=version,
            change_type=change_type,
            author=author,
            diff_json=diff_json,
            yaml_snapshot=yaml_snapshot,
            changed_at=datetime.now(UTC).isoformat(),
        )
        async with self._session_factory() as session:
            async with session.begin():
                session.add(row)
            await session.refresh(row)
            return row

    async def list_for_rule(self, rule_id: str) -> list[RuleChangeLogRow]:
        async with self._session_factory() as session:
            q = (
                select(RuleChangeLogRow)
                .where(RuleChangeLogRow.rule_id == rule_id)
                .order_by(RuleChangeLogRow.id.desc())
            )
            result = await session.execute(q)
            return list(result.scalars().all())
