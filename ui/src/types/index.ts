// ── Enums ─────────────────────────────────────────────────────────────────────

export type EventCategory = 'file' | 'process' | 'network' | 'user' | 'device' | 'log' | 'audit'
export type OS = 'linux' | 'windows' | 'darwin'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical'
export type AlertStatus = 'open' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive'
export type CaseStatus = 'open' | 'in_progress' | 'resolved' | 'archived'
export type IncidentStatus = 'open' | 'investigating' | 'resolved'
export type DecisionType =
  | 'ALERT'
  | 'IGNORE'
  | 'ESCALATE'
  | 'INVESTIGATE'
  | 'ISOLATE'
  | 'REQUEST_HUMAN'
  | 'COLLECT_MORE'
  | 'NOTIFY'
export type HumanDecision = 'approved' | 'rejected'
export type EvidenceType = 'event' | 'file_hash' | 'screenshot' | 'note' | 'external'
export type RuleSource = 'builtin' | 'custom' | 'imported'
export type TIIndicatorType = 'ip' | 'hash'
export type WSStatus = 'connecting' | 'connected' | 'disconnected' | 'error'

// ── Shared ────────────────────────────────────────────────────────────────────

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export interface TokenResponse {
  access_token: string
  token_type: string
}

// ── Event ─────────────────────────────────────────────────────────────────────

export interface UniversalEvent {
  event_id: string
  timestamp_ns: number
  hostname: string
  agent_id: string
  category: EventCategory
  type: string
  severity: Severity
  collector: string
  os: OS
  uid: number
  gid: number
  pid: number
  ppid: number
  process_name: string
  executable: string
  cmdline: string
  cwd: string
  session_id: number | null
  resource: string
  result: string
  file_hash_before: string | null
  file_hash_after: string | null
  src_ip: string | null
  src_port: number | null
  dst_ip: string | null
  dst_port: number | null
  protocol: string | null
  bytes_sent: number | null
  bytes_recv: number | null
  hash_chain: string
  signature: string | null
  ml_score: number | null
  risk_score: number | null
  rule_match_ids: string[]
  mitre_techniques: string[]
  ti_tags: string[]
  incident_chain_id: string | null
  extra: Record<string, unknown>
}

// ── Alert ─────────────────────────────────────────────────────────────────────

export interface AlertNote {
  note_id: string
  created_at: string
  updated_at: string | null
  author: string
  content: string
}

export interface Alert {
  alert_id: string
  created_at: string
  updated_at: string
  severity: AlertSeverity
  status: AlertStatus
  rule_id: string | null
  ml_triggered: boolean
  ti_triggered: boolean
  entity_id: string
  hostname: string
  trigger_event_id: string
  related_event_ids: string[]
  incident_chain_id: string | null
  title: string
  description: string
  mitre_techniques: string[]
  assigned_to: string | null
  notes: AlertNote[]
  false_positive_count: number
}

export interface AlertStats {
  by_severity: Record<AlertSeverity, number>
  open: number
}

// ── Decision ──────────────────────────────────────────────────────────────────

export interface Decision {
  decision_id: string
  created_at: string
  decision_type: DecisionType
  rule_score: number
  ml_score: number
  ti_score: number
  correlation_depth: number
  final_score: number
  entity_id: string
  trigger_alert_id: string | null
  incident_chain_id: string | null
  related_event_ids: string[]
  policy_version: string
  explanation: string
  requires_human: boolean
  human_decision: HumanDecision | null
  human_operator: string | null
  human_note: string | null
  approved_at: string | null
  timeout_at: string | null
  prev_journal_hash: string
  journal_hash: string
}

// ── Case ──────────────────────────────────────────────────────────────────────

export interface CustodyEntry {
  timestamp: string
  operator: string
  action: string
  detail: string
  hash: string
}

export interface EvidenceItem {
  evidence_id: string
  type: EvidenceType
  content: string
  description: string | null
  added_by: string
  added_at: string
  marked_as_evidence_at: string
}

export interface CaseNote {
  note_id: string
  case_id: string
  created_at: string
  updated_at: string | null
  author: string
  content: string
}

export interface ForensicCase {
  case_id: string
  created_at: string
  updated_at: string
  title: string
  description: string
  severity: AlertSeverity
  status: CaseStatus
  tags: string[]
  assigned_to: string | null
  created_by: string
  event_ids: string[]
  alert_ids: string[]
  evidence: EvidenceItem[]
  notes: CaseNote[]
  custody_log: CustodyEntry[]
}

// ── Rule ──────────────────────────────────────────────────────────────────────

export interface Rule {
  id: string
  name: string
  enabled: boolean
  severity: Severity
  condition_yaml: string
  timeframe: number | null
  actions: string[]
  tags: string[]
  mitre: string[]
  explanation: string
  match_count: number
  last_matched: string | null
  false_positive_count: number
  source: RuleSource
}

export interface RuleValidateResponse {
  valid: boolean
  error: string | null
}

// ── Incident ──────────────────────────────────────────────────────────────────

export interface IncidentEvent {
  alert_id: string
  timestamp: string
  severity: AlertSeverity
  title: string
  hostname: string
  mitre_techniques: string[]
}

export interface Incident {
  incident_id: string
  created_at: string
  updated_at: string
  hostname: string
  severity: AlertSeverity
  status: IncidentStatus
  alert_ids: string[]
  timeline: IncidentEvent[]
  mitre_tactics: string[]
  correlation_rule: string
  timeframe_seconds: number
  alert_count: number
}

// ── Policy ────────────────────────────────────────────────────────────────────

export interface CollectorConfig {
  enabled: boolean
  throttle: number
  params: Record<string, unknown>
}

export interface SurveillanceProfile {
  name: string
  description: string
  version: number
  platforms: OS[]
  collectors: Record<string, CollectorConfig>
  ignore_uids: number[]
  ignore_paths_prefix: string[]
  ignore_processes: string[]
  min_severity: Severity
  push_interval_s: number
  created_at: string
  updated_at: string
}

// ── Plugin ────────────────────────────────────────────────────────────────────

export interface PluginInfo {
  name: string
  status: string
  pid: number | null
  error: string | null
}

// ── Threat Intel ──────────────────────────────────────────────────────────────

export interface ThreatIntelReport {
  indicator: string
  indicator_type: TIIndicatorType
  score: number
  malicious: boolean
  provider: string
  tags: string[]
  last_seen: string | null
  raw: Record<string, unknown>
  cached_at: string
}

export interface AggregatedTIReport {
  indicator: string
  indicator_type: TIIndicatorType
  max_score: number
  malicious: boolean
  providers: string[]
  tags: string[]
  reports: ThreatIntelReport[]
  queried_at: string
  ti_unavailable: boolean
}

// ── Snapshot ──────────────────────────────────────────────────────────────────

export interface ProcessInfo {
  pid: number
  ppid: number
  name: string
  exe: string
  cmdline: string
  uid: number
  status: string
}

export interface ConnectionInfo {
  proto: string
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  state: string
  pid: number
}

export interface AgentSnapshot {
  snapshot_id: string
  agent_id: string
  hostname: string
  taken_at: string
  processes: ProcessInfo[]
  connections: ConnectionInfo[]
  case_id: string | null
}

// ── API Keys ──────────────────────────────────────────────────────────────────

export interface ApiKeyCreated {
  key: string
  key_id: string
  name: string
  roles: string[]
}

export interface ApiKeyResponse {
  key_id: string
  name: string
  roles: string[]
  created_at: string
  expires_at: string | null
  revoked: boolean
  created_by: string
}
