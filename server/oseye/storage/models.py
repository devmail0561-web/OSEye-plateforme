"""SQLAlchemy ORM models for OSEye storage.

Maps Pydantic schema models to SQL tables.
- events, alerts, alert_notes, decisions, forensic_cases, custody_log, evidence_items, case_notes
- incidents, incident_alerts
- blocked_agents
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, Index, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "events"

    # Identity
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    timestamp_ns: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Classification
    category: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    collector: Mapped[str] = mapped_column(String(64), nullable=False)
    os: Mapped[str] = mapped_column(String(16), nullable=False, default="linux")

    # Subject identity
    uid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    gid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pid: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    ppid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    process_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    executable: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cmdline: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cwd: Mapped[str] = mapped_column(Text, nullable=False, default="")
    session_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Target resource
    resource: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result: Mapped[str] = mapped_column(String(32), nullable=False, default="success")

    # File hashes
    file_hash_before: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_hash_after: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Network fields
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_recv: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # Integrity
    hash_chain: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Server-side enrichments
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    rule_match_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    mitre_techniques: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    ti_tags: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    incident_chain_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    extra: Mapped[str] = mapped_column(Text, nullable=False, default="{}")  # JSON


class AlertRow(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # PC-15: timestamps are stored as ISO-8601 strings (String(64)) for SQLite
    # compatibility. String comparison is correct for ISO-8601 dates (they sort
    # lexicographically). In a PostgreSQL-only deployment, consider migrating to
    # DateTime(timezone=True) for native temporal queries and range indexes.
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ml_triggered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    ti_triggered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    trigger_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    related_event_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    incident_chain_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mitre_techniques: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON

    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    false_positive_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Context fields required for ISOLATE / KILL_PROCESS response actions (D-R-02)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")


class AlertNoteRow(Base):
    __tablename__ = "alert_notes"

    note_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class DecisionRow(Base):
    """Immutable — no UPDATE or DELETE (enforced by PostgreSQL triggers via SEC-0002)."""

    __tablename__ = "decisions"

    decision_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    decision_type: Mapped[str] = mapped_column(String(32), nullable=False)

    # Input signals
    rule_score: Mapped[float] = mapped_column(Float, nullable=False)
    ml_score: Mapped[float] = mapped_column(Float, nullable=False)
    ti_score: Mapped[float] = mapped_column(Float, nullable=False)
    correlation_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    final_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Context
    entity_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    trigger_alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    incident_chain_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    related_event_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON

    # Policy
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    # Human approval
    requires_human: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    human_decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    human_operator: Mapped[str | None] = mapped_column(String(255), nullable=True)
    human_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    timeout_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Immutable journal
    prev_journal_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    journal_hash: Mapped[str] = mapped_column(String(128), nullable=False)


class ForensicCaseRow(Base):
    __tablename__ = "forensic_cases"

    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    tags: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON

    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)

    event_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    alert_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON


class CustodyLogRow(Base):
    """Immutable — no UPDATE or DELETE (enforced by PostgreSQL triggers via SEC-0002)."""

    __tablename__ = "custody_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    operator: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    hash: Mapped[str] = mapped_column(String(128), nullable=False)


class EvidenceItemRow(Base):
    __tablename__ = "evidence_items"

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    added_by: Mapped[str] = mapped_column(String(255), nullable=False)
    added_at: Mapped[str] = mapped_column(String(64), nullable=False)
    marked_as_evidence_at: Mapped[str] = mapped_column(String(64), nullable=False)


class CaseNoteRow(Base):
    __tablename__ = "case_notes"

    note_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    author: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class ApiKeyRow(Base):
    __tablename__ = "api_keys"

    key_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    roles: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON list
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)


class RuleVersionRow(Base):
    __tablename__ = "rule_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    logged_at: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)  # "false_positive"
    alert_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    operator: Mapped[str] = mapped_column(String(255), nullable=False)
    false_positive_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class IncidentRow(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_hostname_status", "hostname", "status"),)

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(32), index=True)
    updated_at: Mapped[str] = mapped_column(String(32), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True, default="open")
    mitre_tactics: Mapped[str] = mapped_column(Text, default="[]")  # JSON
    correlation_rule: Mapped[str] = mapped_column(String(100))
    timeframe_seconds: Mapped[int] = mapped_column(Integer, default=300)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_ids: Mapped[str] = mapped_column(Text, default="[]")  # JSON


class IncidentAlertRow(Base):
    __tablename__ = "incident_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(36), index=True)
    alert_id: Mapped[str] = mapped_column(String(36), index=True, unique=True)
    added_at: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(500))
    hostname: Mapped[str] = mapped_column(String(255))
    mitre_techniques: Mapped[str] = mapped_column(Text, default="[]")  # JSON


class SnapshotRow(Base):
    __tablename__ = "snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    taken_at: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    processes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")    # JSON
    connections: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)


class EntityHourlyStatsRow(Base):
    """Pre-aggregated per-entity stats used as ML feature inputs.

    Populated by a periodic SQL job (or ClickHouse materialised view in prod).
    One row per (hostname, category, hour_bucket).  The ``hour_bucket`` value
    is a Unix timestamp truncated to the start of the hour
    (i.e. timestamp_ns // 3_600_000_000_000 * 3_600).

    Columns mirror the 10-dim feature vector from ``ml_engine/features.py``
    so the ML worker can back-fill cold-start models from historical aggregates.
    """

    __tablename__ = "entity_hourly_stats"
    __table_args__ = (
        Index("ix_ehs_hostname_cat_hour", "hostname", "category", "hour_bucket"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # Unix timestamp truncated to hour start (timestamp_ns // 3_600_000_000_000 * 3_600)
    hour_bucket: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Aggregates used as ML features
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    uid_p50: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    root_fraction: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    error_fraction: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    distinct_processes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    bytes_sent_sum: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    bytes_recv_sum: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    network_event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    distinct_dst_ips: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class BlockedAgentRow(Base):
    """Persisted blocklist of revoked agent CNs.

    Loaded at startup into AgentServiceServicer._blocked_cns so revocations
    survive server restarts.
    """

    __tablename__ = "blocked_agents"

    cn: Mapped[str] = mapped_column(String(253), primary_key=True)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class ResponseActionRow(Base):
    """Persistent record of a response action sent to an agent.

    Stays in 'pending_report' until the agent confirms via ReportActions RPC.
    Stays in 'executed' until the admin rolls it back (or it is auto-expired).
    CIA — Disponibilité : this table is the authoritative source for the admin
    dashboard — visible even if the agent is offline.
    """

    __tablename__ = "response_actions"

    command_id:     Mapped[str]            = mapped_column(String(36),  primary_key=True)
    decision_id:    Mapped[str]            = mapped_column(String(36),  nullable=False, index=True)
    agent_cn:       Mapped[str]            = mapped_column(String(253), nullable=False, index=True)
    command_type:   Mapped[str]            = mapped_column(String(32),  nullable=False)
    payload:        Mapped[str]            = mapped_column(Text,        nullable=False, default="{}")  # noqa: E501
    # status: pending_report | executed | failed | rolled_back
    status:         Mapped[str]            = mapped_column(String(32),  nullable=False, default="pending_report")  # noqa: E501
    created_at:     Mapped[datetime]       = mapped_column(DateTime(timezone=True), nullable=False)
    executed_at:    Mapped[datetime | None]= mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None]= mapped_column(DateTime(timezone=True), nullable=True)
    error:          Mapped[str | None]     = mapped_column(Text, nullable=True)


class AgentRow(Base):
    """Tracks connected agents — updated on gRPC stream events."""

    __tablename__ = "agents"

    cn:             Mapped[str]            = mapped_column(String(253), primary_key=True)
    first_seen:     Mapped[datetime]       = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen:      Mapped[datetime]       = mapped_column(DateTime(timezone=True), nullable=False)
    version:        Mapped[str | None]     = mapped_column(String(64),  nullable=True)
    active_profile: Mapped[str]            = mapped_column(String(64),  nullable=False, default="workstation")  # noqa: E501
    ip_address:     Mapped[str | None]     = mapped_column(String(45),  nullable=True)
    online:         Mapped[bool]           = mapped_column(Boolean,     nullable=False, default=False)  # noqa: E501
    platform:       Mapped[str]            = mapped_column(String(16),  nullable=False, default="linux", server_default="linux")  # noqa: E501
