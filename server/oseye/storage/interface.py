"""Repository Protocols — all storage backends must satisfy these interfaces."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from oseye.core.schema import Alert, Decision, ForensicCase, UniversalEvent


class Pagination(Protocol):
    limit: int
    offset: int


class EventFilter(Protocol):
    hostname: str | None
    category: str | None
    type: str | None
    severity: str | None
    uid: int | None
    pid: int | None
    process_name: str | None
    resource: str | None
    rule_id: str | None
    mitre_technique: str | None
    from_ts: int | None   # nanoseconds
    to_ts: int | None     # nanoseconds
    agent_id: UUID | None
    incident_chain_id: UUID | None


class Page[T]:
    items: list[T]
    total: int
    limit: int
    offset: int


class EventRepository(Protocol):
    async def insert_batch(self, events: list[UniversalEvent]) -> None: ...
    async def get(self, event_id: UUID) -> UniversalEvent | None: ...
    async def query(self, filters: EventFilter, pagination: Pagination) -> Page: ...
    async def count(self, filters: EventFilter) -> int: ...


class AlertRepository(Protocol):
    async def create(self, alert: Alert) -> Alert: ...
    async def get(self, alert_id: UUID) -> Alert | None: ...
    async def update(self, alert: Alert) -> Alert: ...
    async def list(self, filters: dict, pagination: Pagination) -> Page: ...
    async def count(self, filters: dict) -> int: ...


class DecisionRepository(Protocol):
    async def create(self, decision: Decision) -> Decision: ...
    async def get(self, decision_id: UUID) -> Decision | None: ...
    async def list(self, filters: dict, pagination: Pagination) -> Page: ...
    async def get_pending(self) -> list[Decision]: ...


class CaseRepository(Protocol):
    async def create(self, case: ForensicCase) -> ForensicCase: ...
    async def get(self, case_id: UUID) -> ForensicCase | None: ...
    async def update(self, case: ForensicCase) -> ForensicCase: ...
    async def list(self, filters: dict, pagination: Pagination) -> Page: ...
    async def append_custody(self, case_id: UUID, entry: dict) -> None: ...
