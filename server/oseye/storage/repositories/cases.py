"""SQL implementation of CaseRepository."""

from __future__ import annotations

import json
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from oseye.core.pagination import PageResult
from oseye.core.schema import CaseNote, CustodyEntry, EvidenceItem, ForensicCase
from oseye.storage.interface import Pagination
from oseye.storage.models import CaseNoteRow, CustodyLogRow, EvidenceItemRow, ForensicCaseRow


def _row_to_case(
    row: ForensicCaseRow,
    custody: list[CustodyEntry] | None = None,
    evidence: list[EvidenceItem] | None = None,
    notes: list[CaseNote] | None = None,
) -> ForensicCase:
    return ForensicCase(
        case_id=UUID(row.case_id),
        created_at=datetime.fromisoformat(row.created_at),
        updated_at=datetime.fromisoformat(row.updated_at),
        title=row.title,
        description=row.description,
        severity=row.severity,  # type: ignore[arg-type]
        status=row.status,  # type: ignore[arg-type]
        tags=json.loads(row.tags),
        assigned_to=row.assigned_to,
        created_by=row.created_by,
        event_ids=[UUID(x) for x in json.loads(row.event_ids)],
        alert_ids=[UUID(x) for x in json.loads(row.alert_ids)],
        evidence=evidence or [],
        notes=notes or [],
        custody_log=custody or [],
    )


def _case_to_row(case: ForensicCase) -> ForensicCaseRow:
    return ForensicCaseRow(
        case_id=str(case.case_id),
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
        title=case.title,
        description=case.description,
        severity=case.severity,
        status=case.status,
        tags=json.dumps(case.tags),
        assigned_to=case.assigned_to,
        created_by=case.created_by,
        event_ids=json.dumps([str(x) for x in case.event_ids]),
        alert_ids=json.dumps([str(x) for x in case.alert_ids]),
    )


def _row_to_custody(row: CustodyLogRow) -> CustodyEntry:
    return CustodyEntry(
        timestamp=datetime.fromisoformat(row.timestamp),
        operator=row.operator,
        action=row.action,
        detail=row.detail,
        hash=row.hash,
    )


def _row_to_evidence(row: EvidenceItemRow) -> EvidenceItem:
    return EvidenceItem(
        evidence_id=UUID(row.evidence_id),
        type=row.type,  # type: ignore[arg-type]
        content=row.content,
        description=row.description,
        added_by=row.added_by,
        added_at=datetime.fromisoformat(row.added_at),
        marked_as_evidence_at=datetime.fromisoformat(row.marked_as_evidence_at),
    )


def _row_to_note(row: CaseNoteRow) -> CaseNote:
    return CaseNote(
        note_id=UUID(row.note_id),
        case_id=UUID(row.case_id),
        created_at=datetime.fromisoformat(row.created_at),
        updated_at=datetime.fromisoformat(row.updated_at) if row.updated_at else None,
        author=row.author,
        content=row.content,
    )


async def _load_case_relations(
    session: AsyncSession, case_id: str
) -> tuple[list[CustodyEntry], list[EvidenceItem], list[CaseNote]]:
    custody_rows = (
        await session.execute(
            select(CustodyLogRow).where(CustodyLogRow.case_id == case_id)
            .order_by(CustodyLogRow.id)
        )
    ).scalars().all()

    evidence_rows = (
        await session.execute(
            select(EvidenceItemRow).where(EvidenceItemRow.case_id == case_id)
        )
    ).scalars().all()

    note_rows = (
        await session.execute(
            select(CaseNoteRow).where(CaseNoteRow.case_id == case_id)
        )
    ).scalars().all()

    return (
        [_row_to_custody(r) for r in custody_rows],
        [_row_to_evidence(r) for r in evidence_rows],
        [_row_to_note(r) for r in note_rows],
    )


class SQLCaseRepository:
    """CaseRepository backed by SQLAlchemy async session."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def create(self, case: ForensicCase) -> ForensicCase:
        async with self._session_factory() as session:
            async with session.begin():
                row = _case_to_row(case)
                session.add(row)
                for entry in case.custody_log:
                    session.add(
                        CustodyLogRow(
                            case_id=str(case.case_id),
                            timestamp=entry.timestamp.isoformat(),
                            operator=entry.operator,
                            action=entry.action,
                            detail=entry.detail,
                            hash=entry.hash,
                        )
                    )
                for ev in case.evidence:
                    session.add(
                        EvidenceItemRow(
                            evidence_id=str(ev.evidence_id),
                            case_id=str(case.case_id),
                            type=ev.type,
                            content=ev.content,
                            description=ev.description,
                            added_by=ev.added_by,
                            added_at=ev.added_at.isoformat(),
                            marked_as_evidence_at=ev.marked_as_evidence_at.isoformat(),
                        )
                    )
                for note in case.notes:
                    session.add(
                        CaseNoteRow(
                            note_id=str(note.note_id),
                            case_id=str(case.case_id),
                            created_at=note.created_at.isoformat(),
                            updated_at=note.updated_at.isoformat() if note.updated_at else None,
                            author=note.author,
                            content=note.content,
                        )
                    )
        return case

    async def get(self, case_id: UUID) -> ForensicCase | None:
        async with self._session_factory() as session:
            row = await session.get(ForensicCaseRow, str(case_id))
            if row is None:
                return None
            custody, evidence, notes = await _load_case_relations(session, str(case_id))
            return _row_to_case(row, custody, evidence, notes)

    async def update(self, case: ForensicCase) -> ForensicCase:
        async with self._session_factory() as session:
            async with session.begin():
                row = await session.get(ForensicCaseRow, str(case.case_id))
                if row is None:
                    raise ValueError(f"Case {case.case_id} not found")
                updated = _case_to_row(case)
                row.updated_at = updated.updated_at
                row.title = updated.title
                row.description = updated.description
                row.severity = updated.severity
                row.status = updated.status
                row.tags = updated.tags
                row.assigned_to = updated.assigned_to
                row.event_ids = updated.event_ids
                row.alert_ids = updated.alert_ids

                # Persist notes that do not yet exist in DB
                existing_note_ids: set[str] = set(
                    (
                        await session.execute(
                            select(CaseNoteRow.note_id).where(
                                CaseNoteRow.case_id == str(case.case_id)
                            )
                        )
                    ).scalars().all()
                )
                for note in case.notes:
                    if str(note.note_id) not in existing_note_ids:
                        session.add(
                            CaseNoteRow(
                                note_id=str(note.note_id),
                                case_id=str(case.case_id),
                                created_at=note.created_at.isoformat(),
                                updated_at=note.updated_at.isoformat() if note.updated_at else None,
                                author=note.author,
                                content=note.content,
                            )
                        )

                # Persist evidence items that do not yet exist in DB
                existing_evidence_ids: set[str] = set(
                    (
                        await session.execute(
                            select(EvidenceItemRow.evidence_id).where(
                                EvidenceItemRow.case_id == str(case.case_id)
                            )
                        )
                    ).scalars().all()
                )
                for ev in case.evidence:
                    if str(ev.evidence_id) not in existing_evidence_ids:
                        session.add(
                            EvidenceItemRow(
                                evidence_id=str(ev.evidence_id),
                                case_id=str(case.case_id),
                                type=ev.type,
                                content=ev.content,
                                description=ev.description,
                                added_by=ev.added_by,
                                added_at=ev.added_at.isoformat(),
                                marked_as_evidence_at=ev.marked_as_evidence_at.isoformat(),
                            )
                        )
        return case

    async def list(
        self, filters: dict[str, object], pagination: Pagination
    ) -> PageResult[ForensicCase]:
        async with self._session_factory() as session:
            stmt = select(ForensicCaseRow)
            if filters.get("status"):
                stmt = stmt.where(ForensicCaseRow.status == filters["status"])
            if filters.get("severity"):
                stmt = stmt.where(ForensicCaseRow.severity == filters["severity"])
            if filters.get("created_by"):
                stmt = stmt.where(ForensicCaseRow.created_by == filters["created_by"])

            count_stmt = select(func.count()).select_from(stmt.subquery())
            total: int = (await session.execute(count_stmt)).scalar_one()

            rows = (
                await session.execute(
                    stmt.offset(pagination.offset).limit(pagination.limit)
                )
            ).scalars().all()
            items = [_row_to_case(r) for r in rows]
            return PageResult(
                items=items, total=total, limit=pagination.limit, offset=pagination.offset
            )

    async def append_custody(self, case_id: UUID, entry: dict[str, str]) -> None:
        """Append a new custody log entry (INSERT only — immutable log)."""
        async with self._session_factory() as session:
            async with session.begin():
                session.add(
                    CustodyLogRow(
                        case_id=str(case_id),
                        timestamp=entry["timestamp"],
                        operator=entry["operator"],
                        action=entry["action"],
                        detail=entry["detail"],
                        hash=entry["hash"],
                    )
                )
