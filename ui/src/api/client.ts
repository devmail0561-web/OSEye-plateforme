import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from 'axios'
import type {
  TokenResponse,
  PaginatedResponse,
  UniversalEvent,
  Alert,
  AlertStats,
  Decision,
  ForensicCase,
  CaseNote,
  EvidenceItem,
  Rule,
  RuleValidateResponse,
  Incident,
  AggregatedTIReport,
  PluginInfo,
  SurveillanceProfile,
  EvidenceType,
  AlertStatus,
  AlertSeverity,
  CaseStatus,
  IncidentStatus,
  ApiKeyCreate,
  ApiKeyCreated,
  ApiKeyResponse,
} from '@/types'

// ── Axios instance ────────────────────────────────────────────────────────────

const api: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_URL ?? '',
  headers: { 'Content-Type': 'application/json' },
})

// Lazy import to avoid circular dependency (authStore imports client, client imports authStore)
let _getToken: (() => string | null) | null = null
let _logout: (() => void) | null = null

export function registerAuthCallbacks(
  getToken: () => string | null,
  logout: () => void,
) {
  _getToken = getToken
  _logout = logout
}

// ── Request interceptor — inject Bearer token ─────────────────────────────────

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = _getToken?.()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ── Response interceptor — 401 refresh + retry ────────────────────────────────

let isRefreshing = false
let refreshQueue: Array<(token: string) => void> = []

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config as InternalAxiosRequestConfig & { _retry?: boolean }
    if (error.response?.status !== 401 || original._retry) {
      return Promise.reject(error)
    }
    original._retry = true

    if (isRefreshing) {
      return new Promise((resolve) => {
        refreshQueue.push((token: string) => {
          original.headers.Authorization = `Bearer ${token}`
          resolve(api(original))
        })
      })
    }

    isRefreshing = true
    try {
      const currentToken = _getToken?.()
      if (!currentToken) throw new Error('No token')
      const { data } = await axios.post<TokenResponse>(
        `${import.meta.env.VITE_API_URL ?? ''}/api/v1/auth/refresh`,
        { token: currentToken },
      )
      const newToken = data.access_token
      refreshQueue.forEach((cb) => cb(newToken))
      refreshQueue = []
      original.headers.Authorization = `Bearer ${newToken}`
      // Update store via a dynamic import to avoid circular dep
      const { useAuthStore } = await import('@/stores/authStore')
      useAuthStore.getState().setToken(newToken)
      return api(original)
    } catch {
      refreshQueue = []
      _logout?.()
      return Promise.reject(error)
    } finally {
      isRefreshing = false
    }
  },
)

// ── Auth ──────────────────────────────────────────────────────────────────────

export const authApi = {
  login(username: string, password: string): Promise<TokenResponse> {
    const form = new URLSearchParams({ username, password, grant_type: 'password' })
    return api
      .post<TokenResponse>('/api/v1/auth/token', form, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      })
      .then((r) => r.data)
  },

  refresh(token: string): Promise<TokenResponse> {
    return api.post<TokenResponse>('/api/v1/auth/refresh', { token }).then((r) => r.data)
  },
}

// ── Events ────────────────────────────────────────────────────────────────────

export interface EventQueryParams {
  hostname?: string
  category?: string
  severity?: string
  from_ts?: number
  to_ts?: number
  agent_id?: string
  limit?: number
  offset?: number
}

export const eventsApi = {
  list(params: EventQueryParams = {}): Promise<PaginatedResponse<UniversalEvent>> {
    return api.get<PaginatedResponse<UniversalEvent>>('/api/v1/events', { params }).then((r) => r.data)
  },

  getById(id: string): Promise<UniversalEvent> {
    return api.get<UniversalEvent>(`/api/v1/events/${id}`).then((r) => r.data)
  },
}

// ── Alerts ────────────────────────────────────────────────────────────────────

export interface AlertQueryParams {
  status?: AlertStatus
  severity?: AlertSeverity
  hostname?: string
  limit?: number
  offset?: number
}

export interface AlertPatch {
  status?: AlertStatus
  assigned_to?: string | null
}

export const alertsApi = {
  list(params: AlertQueryParams = {}): Promise<PaginatedResponse<Alert>> {
    return api.get<PaginatedResponse<Alert>>('/api/v1/alerts', { params }).then((r) => r.data)
  },

  stats(): Promise<AlertStats> {
    return api.get<AlertStats>('/api/v1/alerts/stats').then((r) => r.data)
  },

  getById(id: string): Promise<Alert> {
    return api.get<Alert>(`/api/v1/alerts/${id}`).then((r) => r.data)
  },

  patch(id: string, body: AlertPatch): Promise<Alert> {
    return api.patch<Alert>(`/api/v1/alerts/${id}`, body).then((r) => r.data)
  },

  acknowledge(id: string): Promise<Alert> {
    return api.post<Alert>(`/api/v1/alerts/${id}/acknowledge`).then((r) => r.data)
  },

  falsePositive(id: string): Promise<Alert> {
    return api.post<Alert>(`/api/v1/alerts/${id}/false-positive`).then((r) => r.data)
  },
}

// ── Decisions ─────────────────────────────────────────────────────────────────

export interface DecisionQueryParams {
  entity_id?: string
  decision_type?: string
  requires_human?: boolean
  page?: number
  page_size?: number
}

export const decisionsApi = {
  list(params: DecisionQueryParams = {}): Promise<PaginatedResponse<Decision>> {
    return api.get<PaginatedResponse<Decision>>('/api/v1/decisions', { params }).then((r) => r.data)
  },

  pending(): Promise<Decision[]> {
    return api.get<Decision[]>('/api/v1/decisions/pending').then((r) => r.data)
  },

  getById(id: string): Promise<Decision> {
    return api.get<Decision>(`/api/v1/decisions/${id}`).then((r) => r.data)
  },

  approve(id: string, note?: string): Promise<Decision> {
    return api.post<Decision>(`/api/v1/decisions/${id}/approve`, { note: note ?? '' }).then((r) => r.data)
  },

  reject(id: string, note?: string): Promise<Decision> {
    return api.post<Decision>(`/api/v1/decisions/${id}/reject`, { note: note ?? '' }).then((r) => r.data)
  },
}

// ── Cases ─────────────────────────────────────────────────────────────────────

export interface CaseQueryParams {
  status_filter?: CaseStatus
  severity?: AlertSeverity
  page?: number
  page_size?: number
}

export interface CaseCreateBody {
  title: string
  severity: AlertSeverity
  description?: string
  tags?: string[]
  alert_ids?: string[]
  event_ids?: string[]
}

export interface CasePatch {
  title?: string
  description?: string
  severity?: AlertSeverity
  status?: CaseStatus
  assigned_to?: string | null
  tags?: string[]
}

export const casesApi = {
  list(params: CaseQueryParams = {}): Promise<PaginatedResponse<ForensicCase>> {
    return api.get<PaginatedResponse<ForensicCase>>('/api/v1/cases', { params }).then((r) => r.data)
  },

  create(body: CaseCreateBody): Promise<ForensicCase> {
    return api.post<ForensicCase>('/api/v1/cases', body).then((r) => r.data)
  },

  getById(id: string): Promise<ForensicCase> {
    return api.get<ForensicCase>(`/api/v1/cases/${id}`).then((r) => r.data)
  },

  patch(id: string, body: CasePatch): Promise<ForensicCase> {
    return api.patch<ForensicCase>(`/api/v1/cases/${id}`, body).then((r) => r.data)
  },

  addNote(id: string, content: string): Promise<CaseNote> {
    return api.post<CaseNote>(`/api/v1/cases/${id}/notes`, { content }).then((r) => r.data)
  },

  addEvidence(
    id: string,
    body: { type: EvidenceType; content: string; description?: string },
  ): Promise<EvidenceItem> {
    return api.post<EvidenceItem>(`/api/v1/cases/${id}/evidence`, body).then((r) => r.data)
  },

  close(id: string, resolution?: string): Promise<ForensicCase> {
    return api.post<ForensicCase>(`/api/v1/cases/${id}/close`, { resolution: resolution ?? '' }).then((r) => r.data)
  },

  timeline(id: string): Promise<Record<string, unknown>[]> {
    return api.get<Record<string, unknown>[]>(`/api/v1/cases/${id}/timeline`).then((r) => r.data)
  },

  custody(id: string): Promise<Record<string, unknown>[]> {
    return api.get<Record<string, unknown>[]>(`/api/v1/cases/${id}/custody`).then((r) => r.data)
  },

  exportJson(id: string): Promise<Blob> {
    return api.get(`/api/v1/cases/${id}/export/json`, { responseType: 'blob' }).then((r) => r.data as Blob)
  },

  exportHtml(id: string): Promise<Blob> {
    return api.get(`/api/v1/cases/${id}/export/html`, { responseType: 'blob' }).then((r) => r.data as Blob)
  },

  exportPdf(id: string): Promise<Blob> {
    return api.get(`/api/v1/cases/${id}/export/pdf`, { responseType: 'blob' }).then((r) => r.data as Blob)
  },

  exportMisp(id: string): Promise<Record<string, unknown>> {
    return api.get<Record<string, unknown>>(`/api/v1/cases/${id}/export/misp`).then((r) => r.data)
  },

  exportThehive(id: string): Promise<Record<string, unknown>> {
    return api.get<Record<string, unknown>>(`/api/v1/cases/${id}/export/thehive`).then((r) => r.data)
  },
}

// ── Rules ─────────────────────────────────────────────────────────────────────

export const rulesApi = {
  list(enabled_only?: boolean): Promise<{ items: Rule[]; total: number }> {
    return api
      .get<{ items: Rule[]; total: number }>('/api/v1/rules', { params: { enabled_only } })
      .then((r) => r.data)
  },

  getById(id: string): Promise<Rule> {
    return api.get<Rule>(`/api/v1/rules/${id}`).then((r) => r.data)
  },

  validate(condition: string, timeframe?: number): Promise<RuleValidateResponse> {
    return api
      .post<RuleValidateResponse>('/api/v1/rules/validate', { condition, timeframe })
      .then((r) => r.data)
  },

  reload(): Promise<{ reloaded: number }> {
    return api.post<{ reloaded: number }>('/api/v1/rules/reload').then((r) => r.data)
  },
}

// ── Incidents ─────────────────────────────────────────────────────────────────

export interface IncidentQueryParams {
  hostname?: string
  status?: IncidentStatus
  page?: number
  page_size?: number
}

export const incidentsApi = {
  list(params: IncidentQueryParams = {}): Promise<PaginatedResponse<Incident>> {
    return api.get<PaginatedResponse<Incident>>('/api/v1/incidents', { params }).then((r) => r.data)
  },

  getById(id: string): Promise<Incident> {
    return api.get<Incident>(`/api/v1/incidents/${id}`).then((r) => r.data)
  },
}

// ── Threat Intel ──────────────────────────────────────────────────────────────

export const tiApi = {
  lookup(params: { ip?: string; hash?: string }): Promise<AggregatedTIReport> {
    return api.get<AggregatedTIReport>('/api/v1/ti/lookup', { params }).then((r) => r.data)
  },
}

// ── Plugins ───────────────────────────────────────────────────────────────────

export const pluginsApi = {
  config(): Promise<{ require_signature: boolean; has_trusted_keys: boolean }> {
    return api.get<{ require_signature: boolean; has_trusted_keys: boolean }>('/api/v1/plugins/config').then((r) => r.data)
  },

  list(): Promise<PluginInfo[]> {
    return api.get<PluginInfo[]>('/api/v1/plugins').then((r) => r.data)
  },

  getById(name: string): Promise<PluginInfo> {
    return api.get<PluginInfo>(`/api/v1/plugins/${name}`).then((r) => r.data)
  },

  upload(file: File, verify = true): Promise<{ name: string; status: string }> {
    const form = new FormData()
    form.append('file', file)
    return api.post<{ name: string; status: string }>(
      `/api/v1/plugins/upload?verify=${verify}`,
      form,
      { headers: { 'Content-Type': 'multipart/form-data' } },
    ).then((r) => r.data)
  },

  install(path: string, verify = true): Promise<{ name: string; status: string }> {
    return api.post<{ name: string; status: string }>('/api/v1/plugins/install', { path, verify }).then((r) => r.data)
  },

  enable(name: string): Promise<{ name: string; status: string; pid: number | null }> {
    return api
      .post<{ name: string; status: string; pid: number | null }>(`/api/v1/plugins/${name}/enable`)
      .then((r) => r.data)
  },

  disable(name: string): Promise<{ name: string; status: string }> {
    return api.post<{ name: string; status: string }>(`/api/v1/plugins/${name}/disable`).then((r) => r.data)
  },

  delete(name: string): Promise<void> {
    return api.delete(`/api/v1/plugins/${name}`).then(() => undefined)
  },
}

// ── Policies ──────────────────────────────────────────────────────────────────

export const policiesApi = {
  list(): Promise<SurveillanceProfile[]> {
    return api.get<SurveillanceProfile[]>('/api/v1/policies').then((r) => r.data)
  },

  getById(name: string): Promise<SurveillanceProfile> {
    return api.get<SurveillanceProfile>(`/api/v1/policies/${name}`).then((r) => r.data)
  },

  apply(name: string, agent_id?: string): Promise<{ profile: string; pushed_to: string }> {
    return api
      .post<{ profile: string; pushed_to: string }>(`/api/v1/policies/${name}/apply`, { agent_id })
      .then((r) => r.data)
  },
}

// ── API Keys ──────────────────────────────────────────────────────────────────

export const apiKeysApi = {
  list(includeRevoked = false): Promise<{ items: ApiKeyResponse[]; total: number }> {
    return api.get<{ items: ApiKeyResponse[]; total: number }>(
      '/api/v1/api-keys',
      { params: { include_revoked: includeRevoked } },
    ).then((r) => r.data)
  },

  create(body: ApiKeyCreate): Promise<ApiKeyCreated> {
    return api.post<ApiKeyCreated>('/api/v1/api-keys', body).then((r) => r.data)
  },

  revoke(key_id: string): Promise<void> {
    return api.delete(`/api/v1/api-keys/${key_id}`).then(() => undefined)
  },
}

// ── Response Actions ──────────────────────────────────────────────────────────

export interface ResponseAction {
  command_id:     string
  decision_id:    string
  agent_cn:       string
  command_type:   string
  payload:        Record<string, unknown>
  status:         'pending_report' | 'executed' | 'failed' | 'rolled_back'
  created_at:     string
  executed_at:    string | null
  rolled_back_at: string | null
  error:          string | null
}

export const responseActionsApi = {
  list(params?: { agent_cn?: string; action_status?: string; limit?: number; offset?: number }): Promise<ResponseAction[]> {
    return api.get<ResponseAction[]>('/api/v1/response-actions', { params }).then((r) => r.data)
  },

  get(command_id: string): Promise<ResponseAction> {
    return api.get<ResponseAction>(`/api/v1/response-actions/${command_id}`).then((r) => r.data)
  },

  rollback(command_id: string): Promise<void> {
    return api.post(`/api/v1/response-actions/${command_id}/rollback`).then(() => undefined)
  },
}

// ── Agents ───────────────────────────────────────────────────────────────────

export interface AgentInfo {
  cn:             string
  online:         boolean
  first_seen:     string | null
  last_seen:      string | null
  version:        string | null
  active_profile: string
  ip_address:     string | null
  platform:       string    // "linux" | "windows" | "darwin"
}

export interface EntityProfile {
  entity_id:    string
  entity_type:  string
  hostname:     string
  risk_score:   number
  alert_count:  number
  last_seen:    string | null
}

export const entitiesApi = {
  list(hostname?: string): Promise<EntityProfile[]> {
    return api.get<EntityProfile[]>('/api/v1/entities', { params: hostname ? { hostname } : {} }).then((r) => r.data)
  },
  get(entityId: string): Promise<EntityProfile> {
    return api.get<EntityProfile>(`/api/v1/entities/${encodeURIComponent(entityId)}`).then((r) => r.data)
  },
}

export const chainApi = {
  get(eventId: string): Promise<UniversalEvent[]> {
    return api.get<UniversalEvent[]>(`/api/v1/events/${eventId}/chain`).then((r) => r.data)
  },
}

export const agentsApi = {
  list(): Promise<AgentInfo[]> {
    return api.get<AgentInfo[]>('/api/v1/agents').then((r) => r.data)
  },
  get(cn: string): Promise<AgentInfo> {
    return api.get<AgentInfo>(`/api/v1/agents/${encodeURIComponent(cn)}`).then((r) => r.data)
  },
}

// ── Enrollment tokens ─────────────────────────────────────────────────────────

export interface EnrollmentToken {
  token_id:   string
  created_at: string
  expires_at: string
  created_by: string
}

export const enrollmentApi = {
  create(expires_in_hours?: number): Promise<{ token: string; token_id: string }> {
    return api
      .post<{ token: string; token_id: string }>('/api/v1/enroll/tokens', {
        expires_in_hours: expires_in_hours ?? null,
      })
      .then((r) => r.data)
  },

  list(): Promise<EnrollmentToken[]> {
    return api.get<EnrollmentToken[]>('/api/v1/enroll/tokens').then((r) => r.data)
  },

  revoke(token_id: string): Promise<void> {
    return api.delete(`/api/v1/enroll/tokens/${token_id}`).then(() => undefined)
  },
}

// ── Health ────────────────────────────────────────────────────────────────────

export const healthApi = {
  check(): Promise<{ status: string; service: string }> {
    return api.get<{ status: string; service: string }>('/api/v1/health').then((r) => r.data)
  },
}

export default api
