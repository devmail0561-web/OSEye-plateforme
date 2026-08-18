"""Canonical data models for OSEye — all components share these types."""

from __future__ import annotations

import ipaddress as _ipaddress
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, BeforeValidator, Field


def _validate_ip(v: object) -> str | None:
    """Normalise IP address fields.

    Valid IPv4/IPv6 addresses are accepted and returned as strings.
    Non-IP values (wildcards, hostnames) are passed through as-is so that
    normalizer adapters that store '*' or domain names are not broken.
    """
    if v is None:
        return None
    s = str(v)
    try:
        _ipaddress.ip_address(s)
    except ValueError:
        # Not a valid IP — pass through (wildcard '*', hostname, etc.)
        pass
    return s


# IP field type: stored as str, validated as a real IP address.
_IPStr = Annotated[str, BeforeValidator(_validate_ip)]

# ---------------------------------------------------------------------------
# Universal Event
# ---------------------------------------------------------------------------

class UniversalEvent(BaseModel):
    # Identity
    event_id: UUID
    timestamp_ns: int
    hostname: str
    agent_id: UUID

    # Classification
    category: Literal["file", "process", "network", "user", "device", "log", "audit"]
    type: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    collector: str
    os: Literal["linux", "windows", "darwin"] = "linux"

    # Subject identity
    uid: int = 0
    gid: int = 0
    pid: int = 0
    ppid: int = 0
    process_name: str = ""
    executable: str = ""
    cmdline: str = ""
    cwd: str = ""
    session_id: int | None = None

    # Target resource
    resource: str = ""
    result: str = "success"

    # File hashes
    file_hash_before: str | None = None
    file_hash_after: str | None = None

    # Network fields
    # _IPStr validates and normalises IP addresses as plain strings (audit M-34).
    # contexts (e.g. TI lookups, log messages) when the raw IPv4Address object
    # is not acceptable.
    src_ip: _IPStr | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_ip: _IPStr | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    bytes_sent: int | None = None
    bytes_recv: int | None = None

    # Integrity
    hash_chain: str = ""
    signature: str | None = None

    # Server-side enrichments (added after collection)
    ml_score: float | None = None
    risk_score: float | None = None
    rule_match_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    ti_tags: list[str] = Field(default_factory=list)
    incident_chain_id: UUID | None = None

    extra: dict[str, object] = Field(default_factory=dict)

    # frozen=False is intentional: server-side enrichment pipeline adds fields
    # (ml_score, risk_score, rule_match_ids, mitre_techniques, ti_tags,
    # incident_chain_id) to events after collection. Immutability would require
    # creating new objects for every enrichment step, which is wasteful.
    model_config = {"frozen": False}


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class AlertNote(BaseModel):
    note_id: UUID
    created_at: datetime
    updated_at: datetime | None = None
    author: str
    content: str


class Alert(BaseModel):
    alert_id: UUID
    created_at: datetime
    updated_at: datetime

    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "acknowledged", "investigating", "resolved", "false_positive"]

    rule_id: str | None = None
    ml_triggered: bool = False
    ti_triggered: bool = False

    entity_id: str
    hostname: str

    trigger_event_id: UUID
    related_event_ids: list[UUID] = Field(default_factory=list)
    incident_chain_id: UUID | None = None

    title: str
    description: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)

    assigned_to: str | None = None
    notes: list[AlertNote] = Field(default_factory=list)
    false_positive_count: int = 0

    # Context fields required for ISOLATE / KILL_PROCESS response actions
    dst_ip: str | None = None
    pid: int | None = None
    process_name: str = ""


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

class Decision(BaseModel):
    decision_id: UUID
    created_at: datetime

    decision_type: Literal[
        "ALERT", "IGNORE", "ESCALATE", "INVESTIGATE",
        "ISOLATE", "REQUEST_HUMAN", "COLLECT_MORE", "NOTIFY"
    ]
    # Full action set produced by the risk matrix (e.g. ["ALERT", "ISOLATE"]).
    # Not persisted to DB — populated in-memory by the engine.
    # Defaults to [] for decisions loaded from DB (only decision_type is stored).
    decision_types: list[str] = Field(default_factory=list)

    # Input signals
    rule_score: float
    ml_score: float
    ti_score: float
    correlation_depth: int
    final_score: float

    # Context
    entity_id: str
    trigger_alert_id: UUID | None = None
    incident_chain_id: UUID | None = None
    related_event_ids: list[UUID] = Field(default_factory=list)

    # Policy applied
    policy_version: str
    explanation: str

    # Human approval
    requires_human: bool = False
    human_decision: Literal["approved", "rejected"] | None = None
    human_operator: str | None = None
    human_note: str | None = None
    approved_at: datetime | None = None
    timeout_at: datetime | None = None

    # Immutable journal
    prev_journal_hash: str
    journal_hash: str


# ---------------------------------------------------------------------------
# Forensic Case
# ---------------------------------------------------------------------------

class CustodyEntry(BaseModel):
    timestamp: datetime
    operator: str
    action: str
    detail: str
    hash: str  # BLAKE3 of this entry


class EvidenceItem(BaseModel):
    evidence_id: UUID
    type: Literal["event", "file_hash", "screenshot", "note", "external"]
    content: str
    description: str | None = None
    added_by: str
    added_at: datetime
    marked_as_evidence_at: datetime


class CaseNote(BaseModel):
    note_id: UUID
    case_id: UUID
    created_at: datetime
    updated_at: datetime | None = None
    author: str
    content: str


class ForensicCase(BaseModel):
    model_config = {"validate_assignment": True}

    case_id: UUID
    created_at: datetime
    updated_at: datetime

    title: str
    description: str = ""
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "in_progress", "resolved", "archived"]
    tags: list[str] = Field(default_factory=list)

    assigned_to: str | None = None
    created_by: str

    event_ids: list[UUID] = Field(default_factory=list)
    alert_ids: list[UUID] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    notes: list[CaseNote] = Field(default_factory=list)
    custody_log: list[CustodyEntry] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule
# ---------------------------------------------------------------------------

class Rule(BaseModel):
    id: str
    name: str
    enabled: bool = True
    severity: Literal["info", "low", "medium", "high", "critical"]
    condition_yaml: str
    timeframe: int | None = None  # seconds for temporal rules
    actions: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    explanation: str = ""

    match_count: int = 0
    last_matched: datetime | None = None
    false_positive_count: int = 0
    source: Literal["builtin", "custom", "imported"] = "custom"


# ---------------------------------------------------------------------------
# Entity Profile
# ---------------------------------------------------------------------------

class EntityProfile(BaseModel):
    entity_id: str
    entity_type: Literal["process", "user", "connection", "file"]
    hostname: str

    risk_score: float = 0.0
    baseline_score: float = 0.0
    alert_count: int = 0
    last_seen: datetime | None = None
    whitelisted: bool = False
    whitelist_expires_at: datetime | None = None

    risk_history: list[tuple[datetime, float]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Surveillance Profile
# ---------------------------------------------------------------------------

class CollectorConfig(BaseModel):
    enabled: bool = True
    throttle: float = 1.0
    params: dict[str, object] = Field(default_factory=dict)


class SurveillanceProfile(BaseModel):
    name: str
    description: str = ""
    version: int = 1
    platforms: list[Literal["linux", "windows", "darwin"]] = Field(default_factory=list)

    collectors: dict[str, CollectorConfig] = Field(default_factory=dict)

    ignore_uids: list[int] = Field(default_factory=list)
    ignore_paths_prefix: list[str] = Field(default_factory=list)
    ignore_processes: list[str] = Field(default_factory=list)

    min_severity: Literal["info", "low", "medium", "high", "critical"] = "low"
    push_interval_s: int = 60

    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Agent Info
# ---------------------------------------------------------------------------

class AgentInfo(BaseModel):
    agent_id: UUID
    hostname: str
    enrolled_at: datetime
    last_seen: datetime | None = None
    cert_serial: str | None = None
    cert_expires_at: datetime | None = None
    active_profile: str = "workstation"
    revoked: bool = False
    online: bool = False
    platform: str = "linux"  # "linux" | "windows" | "darwin"


# ---------------------------------------------------------------------------
# Correlation / Incident
# ---------------------------------------------------------------------------

class IncidentEvent(BaseModel):
    alert_id: UUID
    timestamp: datetime
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    hostname: str
    mitre_techniques: list[str] = []


class Incident(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    hostname: str
    severity: Literal["low", "medium", "high", "critical"]
    status: Literal["open", "investigating", "resolved"] = "open"
    alert_ids: list[UUID] = []
    timeline: list[IncidentEvent] = []
    mitre_tactics: list[str] = []
    correlation_rule: str = "same_host_timeframe"
    timeframe_seconds: int = 300
    alert_count: int = 0


# ---------------------------------------------------------------------------
# Agent Snapshot
# ---------------------------------------------------------------------------

class ProcessInfo(BaseModel):
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: str
    uid: int
    status: str  # "running", "sleeping", "zombie", etc.


class ConnectionInfo(BaseModel):
    proto: str   # "tcp", "udp"
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str   # "ESTABLISHED", "LISTEN", etc.
    pid: int


class AgentSnapshot(BaseModel):
    snapshot_id: UUID
    agent_id: UUID
    hostname: str
    taken_at: datetime
    processes: list[ProcessInfo] = Field(default_factory=list)
    connections: list[ConnectionInfo] = Field(default_factory=list)
    case_id: UUID | None = None  # optionally linked to a ForensicCase
