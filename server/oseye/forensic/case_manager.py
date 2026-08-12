"""Business facade over SQLCaseRepository with chained-hash custody log."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from oseye.core.pagination import PageResult
from oseye.core.schema import CaseNote, CustodyEntry, EvidenceItem, ForensicCase
from oseye.storage.interface import Pagination
from oseye.storage.repositories.cases import SQLCaseRepository


def _custody_hash(prev_hash: str, timestamp: str, operator: str, action: str, detail: str) -> str:
    """BLAKE2b-256 of a pipe-delimited string for tamper-evident chaining."""
    data = f"{prev_hash}|{timestamp}|{operator}|{action}|{detail}".encode()
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def _last_hash(case: ForensicCase) -> str:
    if case.custody_log:
        return case.custody_log[-1].hash
    return "0" * 64


class CaseManager:
    """High-level case operations with automatic custody log maintenance."""

    def __init__(self, case_repo: SQLCaseRepository) -> None:
        self._repo = case_repo
        self._case_locks: dict[UUID, asyncio.Lock] = {}

    async def _get_case_lock(self, case_id: UUID) -> asyncio.Lock:
        if case_id not in self._case_locks:
            self._case_locks[case_id] = asyncio.Lock()
        return self._case_locks[case_id]

    async def _append_custody(
        self,
        case: ForensicCase,
        operator: str,
        action: str,
        detail: str,
    ) -> CustodyEntry:
        now = datetime.now(UTC)
        ts = now.isoformat()
        prev = _last_hash(case)
        h = _custody_hash(prev, ts, operator, action, detail)
        entry = CustodyEntry(timestamp=now, operator=operator, action=action, detail=detail, hash=h)
        await self._repo.append_custody(
            case.case_id,
            {"timestamp": ts, "operator": operator, "action": action, "detail": detail, "hash": h},
        )
        return entry

    async def create_case(
        self,
        title: str,
        severity: str,
        created_by: str,
        description: str = "",
        tags: list[str] | None = None,
        alert_ids: list[UUID] | None = None,
        event_ids: list[UUID] | None = None,
    ) -> ForensicCase:
        now = datetime.now(UTC)
        case = ForensicCase(
            case_id=uuid4(),
            created_at=now,
            updated_at=now,
            title=title,
            description=description,
            severity=severity,  # type: ignore[arg-type]
            status="open",
            tags=tags or [],
            created_by=created_by,
            alert_ids=alert_ids or [],
            event_ids=event_ids or [],
        )
        ts = now.isoformat()
        h = _custody_hash("0" * 64, ts, created_by, "case_opened", title)
        case.custody_log.append(
            CustodyEntry(
                timestamp=now, operator=created_by, action="case_opened", detail=title, hash=h
            )
        )
        return await self._repo.create(case)

    async def get_case(self, case_id: UUID) -> ForensicCase | None:
        return await self._repo.get(case_id)

    async def update_case(self, case_id: UUID, operator: str, **fields: Any) -> ForensicCase:
        async with await self._get_case_lock(case_id):
            case = await self._repo.get(case_id)
            if case is None:
                raise ValueError(f"Case {case_id} not found")
            for k, v in fields.items():
                object.__setattr__(case, k, v)
            case.updated_at = datetime.now(UTC)
            await self._repo.update(case)
            detail = ", ".join(f"{k}={v}" for k, v in fields.items())
            await self._append_custody(case, operator, "case_updated", detail)
            return case

    async def add_note(self, case_id: UUID, author: str, content: str) -> CaseNote:
        async with await self._get_case_lock(case_id):
            case = await self._repo.get(case_id)
            if case is None:
                raise ValueError(f"Case {case_id} not found")
            now = datetime.now(UTC)
            note = CaseNote(
                note_id=uuid4(),
                case_id=case_id,
                created_at=now,
                author=author,
                content=content,
            )
            case.notes.append(note)
            case.updated_at = now
            await self._repo.update(case)
            await self._append_custody(case, author, "note_added", content[:200])
            return note

    async def add_evidence(
        self,
        case_id: UUID,
        operator: str,
        type_: str,
        content: str,
        description: str | None = None,
    ) -> EvidenceItem:
        async with await self._get_case_lock(case_id):
            case = await self._repo.get(case_id)
            if case is None:
                raise ValueError(f"Case {case_id} not found")
            now = datetime.now(UTC)
            item = EvidenceItem(
                evidence_id=uuid4(),
                type=type_,  # type: ignore[arg-type]
                content=content,
                description=description,
                added_by=operator,
                added_at=now,
                marked_as_evidence_at=now,
            )
            case.evidence.append(item)
            case.updated_at = now
            await self._repo.update(case)
            detail = description or content[:200]
            await self._append_custody(case, operator, "evidence_added", detail)
            return item

    async def close_case(self, case_id: UUID, operator: str, resolution: str) -> ForensicCase:
        async with await self._get_case_lock(case_id):
            case = await self._repo.get(case_id)
            if case is None:
                raise ValueError(f"Case {case_id} not found")
            case.status = "resolved"
            case.updated_at = datetime.now(UTC)
            await self._repo.update(case)
            await self._append_custody(case, operator, "case_closed", resolution)
            return case

    async def list_cases(
        self, filters: dict[str, object], pagination: Pagination
    ) -> PageResult[ForensicCase]:
        return await self._repo.list(filters, pagination)
