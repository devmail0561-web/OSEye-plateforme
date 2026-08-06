"""SQL implementation of DecisionRepository.

Decisions are IMMUTABLE — only INSERT is ever performed (SEC-0002).
No UPDATE or DELETE operations are issued by this repository.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.core.schema import Decision
from oseye.storage.interface import Pagination
from oseye.storage.models import DecisionRow


@dataclass
class PageResult[T]:
    items: list[T]
    total: int
    limit: int
    offset: int


def _row_to_decision(row: DecisionRow) -> Decision:
    from datetime import datetime

    return Decision(
        decision_id=UUID(row.decision_id),
        created_at=datetime.fromisoformat(row.created_at),
        decision_type=row.decision_type,  # type: ignore[arg-type]
        rule_score=row.rule_score,
        ml_score=row.ml_score,
        ti_score=row.ti_score,
        correlation_depth=row.correlation_depth,
        final_score=row.final_score,
        entity_id=row.entity_id,
        trigger_alert_id=UUID(row.trigger_alert_id) if row.trigger_alert_id else None,
        incident_chain_id=UUID(row.incident_chain_id) if row.incident_chain_id else None,
        related_event_ids=[UUID(x) for x in json.loads(row.related_event_ids)],
        policy_version=row.policy_version,
        explanation=row.explanation,
        requires_human=row.requires_human,
        human_decision=row.human_decision,  # type: ignore[arg-type]
        human_operator=row.human_operator,
        human_note=row.human_note,
        approved_at=datetime.fromisoformat(row.approved_at) if row.approved_at else None,
        timeout_at=datetime.fromisoformat(row.timeout_at) if row.timeout_at else None,
        prev_journal_hash=row.prev_journal_hash,
        journal_hash=row.journal_hash,
    )


def _decision_to_row(decision: Decision) -> DecisionRow:
    return DecisionRow(
        decision_id=str(decision.decision_id),
        created_at=decision.created_at.isoformat(),
        decision_type=decision.decision_type,
        rule_score=decision.rule_score,
        ml_score=decision.ml_score,
        ti_score=decision.ti_score,
        correlation_depth=decision.correlation_depth,
        final_score=decision.final_score,
        entity_id=decision.entity_id,
        trigger_alert_id=str(decision.trigger_alert_id) if decision.trigger_alert_id else None,
        incident_chain_id=(
            str(decision.incident_chain_id) if decision.incident_chain_id else None
        ),
        related_event_ids=json.dumps([str(x) for x in decision.related_event_ids]),
        policy_version=decision.policy_version,
        explanation=decision.explanation,
        requires_human=decision.requires_human,
        human_decision=decision.human_decision,
        human_operator=decision.human_operator,
        human_note=decision.human_note,
        approved_at=decision.approved_at.isoformat() if decision.approved_at else None,
        timeout_at=decision.timeout_at.isoformat() if decision.timeout_at else None,
        prev_journal_hash=decision.prev_journal_hash,
        journal_hash=decision.journal_hash,
    )


class SQLDecisionRepository:
    """DecisionRepository backed by SQLAlchemy async session.

    Only INSERT operations are ever issued against the decisions table.
    UPDATE and DELETE are prohibited at the application layer and enforced
    at the database layer via PostgreSQL triggers (SEC-0002).
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, decision: Decision) -> Decision:
        async with self._session_factory() as session:
            async with session.begin():
                row = _decision_to_row(decision)
                session.add(row)
        return decision

    async def get(self, decision_id: UUID) -> Decision | None:
        async with self._session_factory() as session:
            row = await session.get(DecisionRow, str(decision_id))
            if row is None:
                return None
            return _row_to_decision(row)

    async def list_decisions(
        self, filters: dict[str, object], pagination: Pagination
    ) -> PageResult[Decision]:
        from sqlalchemy import func

        async with self._session_factory() as session:
            stmt = select(DecisionRow)
            if filters.get("entity_id"):
                stmt = stmt.where(DecisionRow.entity_id == filters["entity_id"])
            if filters.get("decision_type"):
                stmt = stmt.where(DecisionRow.decision_type == filters["decision_type"])
            if filters.get("requires_human"):
                stmt = stmt.where(DecisionRow.requires_human == filters["requires_human"])

            count_stmt = select(func.count()).select_from(stmt.subquery())
            total: int = (await session.execute(count_stmt)).scalar_one()

            rows = (
                await session.execute(
                    stmt.offset(pagination.offset)
                    .limit(pagination.limit)
                    .order_by(DecisionRow.created_at.desc())
                )
            ).scalars().all()
            items = [_row_to_decision(r) for r in rows]
            return PageResult(
                items=items, total=total, limit=pagination.limit, offset=pagination.offset
            )

    async def get_pending(self) -> list[Decision]:
        async with self._session_factory() as session:
            stmt = select(DecisionRow).where(
                DecisionRow.requires_human.is_(True),
                DecisionRow.human_decision.is_(None),
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_decision(r) for r in rows]
