"""Repository for admin-managed rules (CRUD via API/CLI)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import RuleChangeLogRow, RuleRow


class SQLRuleRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, row: RuleRow) -> RuleRow:
        async with self._session_factory() as session:
            async with session.begin():
                session.add(row)
                session.add(RuleChangeLogRow(
                    rule_id=row.rule_id,
                    version=row.version,
                    change_type="created",
                    author=row.author,
                    yaml_snapshot=row.yaml_content or None,
                    changed_at=datetime.now(UTC).isoformat(),
                ))
            await session.refresh(row)
            return row

    async def get(self, rule_id: str) -> RuleRow | None:
        async with self._session_factory() as session:
            return await session.get(RuleRow, rule_id)

    async def list(self, enabled_only: bool = False) -> list[RuleRow]:
        async with self._session_factory() as session:
            q = select(RuleRow).order_by(RuleRow.created_at.desc())
            if enabled_only:
                q = q.where(RuleRow.enabled.is_(True))
            result = await session.execute(q)
            return list(result.scalars().all())

    async def update(self, rule_id: str, **fields: object) -> RuleRow | None:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(RuleRow, rule_id)
                if row is None:
                    return None
                fields["updated_at"] = datetime.now(UTC).isoformat()
                if "name" in fields or "config_json" in fields or "yaml_content" in fields:
                    row.version = row.version + 1
                old_vals = {k: getattr(row, k, None) for k in fields}
                for key, val in fields.items():
                    setattr(row, key, val)
                diff = {k: {"from": old_vals[k], "to": fields[k]} for k in fields
                        if old_vals.get(k) != fields[k]}
                session.add(RuleChangeLogRow(
                    rule_id=row.rule_id,
                    version=row.version,
                    change_type="updated",
                    author=str(fields.get("author") or row.author or ""),
                    diff_json=json.dumps(diff),
                    yaml_snapshot=str(fields.get("yaml_content") or row.yaml_content or ""),
                    changed_at=datetime.now(UTC).isoformat(),
                ))
            await session.refresh(row)
            return row

    async def delete(self, rule_id: str) -> bool:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(RuleRow, rule_id)
                if row is None:
                    return False
                session.add(RuleChangeLogRow(
                    rule_id=rule_id,
                    version=row.version,
                    change_type="deleted",
                    author=row.author,
                    yaml_snapshot=row.yaml_content or None,
                    changed_at=datetime.now(UTC).isoformat(),
                ))
                await session.delete(row)
            return True

    async def get_history(self, rule_id: str) -> list[RuleChangeLogRow]:
        async with self._session_factory() as session:
            q = (
                select(RuleChangeLogRow)
                .where(RuleChangeLogRow.rule_id == rule_id)
                .order_by(RuleChangeLogRow.id.desc())
            )
            result = await session.execute(q)
            return list(result.scalars().all())
