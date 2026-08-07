"""SQL repository for rule_versions — feedback false positive log."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.storage.models import RuleVersionRow


class SQLRuleVersionRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def log_false_positive(
        self,
        rule_id: str,
        alert_id: str,
        operator: str,
        false_positive_count: int,
    ) -> None:
        row = RuleVersionRow(
            rule_id=rule_id,
            logged_at=datetime.now(UTC).isoformat(),
            event_type="false_positive",
            alert_id=alert_id,
            operator=operator,
            false_positive_count=false_positive_count,
        )
        async with self._session_factory() as session:
            async with session.begin():
                session.add(row)
