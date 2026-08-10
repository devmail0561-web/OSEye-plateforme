import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const { mockList } = vi.hoisted(() => ({ mockList: vi.fn() }))

vi.mock('@/api/client', () => ({
  incidentsApi: { list: mockList },
}))

import Incidents from './Incidents'

const FAKE_INCIDENT = {
  incident_id: 'inc-1',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  hostname: 'compromised-host',
  severity: 'critical' as const,
  status: 'investigating' as const,
  alert_ids: ['a1', 'a2', 'a3'],
  timeline: [],
  mitre_tactics: ['TA0002', 'TA0003'],
  correlation_rule: 'lateral_movement',
  timeframe_seconds: 300,
  alert_count: 3,
}

function renderIncidents() {
  return render(<MemoryRouter><Incidents /></MemoryRouter>)
}

describe('Incidents', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockList.mockResolvedValue({ items: [FAKE_INCIDENT], total: 1, limit: 25, offset: 0 })
  })

  it('renders incident row with hostname', async () => {
    renderIncidents()
    await waitFor(() => expect(screen.getByText('compromised-host')).toBeInTheDocument())
  })

  it('renders alert count', async () => {
    renderIncidents()
    await waitFor(() => screen.getByText('compromised-host'))
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('renders MITRE tactics', async () => {
    renderIncidents()
    await waitFor(() => screen.getByText('TA0002'))
  })

  it('renders correlation rule', async () => {
    renderIncidents()
    await waitFor(() => screen.getByText('lateral_movement'))
  })

  it('shows empty state when no incidents', async () => {
    mockList.mockResolvedValue({ items: [], total: 0, limit: 25, offset: 0 })
    renderIncidents()
    await waitFor(() => expect(screen.getByText(/aucun incident/i)).toBeInTheDocument())
  })

  it('renders total count', async () => {
    renderIncidents()
    await waitFor(() => screen.getByText('compromised-host'))
    expect(screen.getByText(/1 incidents au total/i)).toBeInTheDocument()
  })
})
