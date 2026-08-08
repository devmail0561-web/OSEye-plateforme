from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ThreatIntelReport(BaseModel):
    indicator: str
    indicator_type: Literal["ip", "hash"]
    score: float = Field(ge=0.0, le=100.0)
    malicious: bool
    provider: str
    tags: list[str] = []
    last_seen: datetime | None = None
    raw: dict[str, object] = {}
    cached_at: datetime


class AggregatedTIReport(BaseModel):
    indicator: str
    indicator_type: Literal["ip", "hash"]
    max_score: float = 0.0
    malicious: bool = False
    providers: list[str] = []
    tags: list[str] = []
    reports: list[ThreatIntelReport] = []
    queried_at: datetime
    # True when all providers failed (circuit open, timeout, errors) — score/malicious not reliable
    ti_unavailable: bool = False
