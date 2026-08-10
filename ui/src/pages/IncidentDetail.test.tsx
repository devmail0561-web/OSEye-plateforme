import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'

const { mockGetById } = vi.hoisted(() => ({ mockGetById: vi.fn() }))

vi.mock('@/api/client', () => ({
  incidentsApi: { getById: mockGetById },
}))

import IncidentDetail from './IncidentDetail'

const FAKE_INCIDENT = {
  incident_id: 'inc-1',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  hostname: 'victim-host',
  severity: 'high' as const,
  status: 'open' as const,
  alert_ids: ['a1', 'a2'],
  timeline: [
    {
      alert_id: 'a1',
      timestamp: new Date().toISOString(),
      severity: 'high' as const,
      title: 'Suspicious network connection',
      hostname: 'victim-host',
      mitre_techniques: ['T1071'],
    },
  ],
  mitre_tactics: ['TA0011', 'TA0007'],
  correlation_rule: 'c2_beacon',
  timeframe_seconds: 120,
  alert_count: 2,
}

function renderDetail(id = 'inc-1') {
  const router = createMemoryRouter(
    [{ path: '/incidents/:id', element: <IncidentDetail /> }],
    { initialEntries: [`/incidents/${id}`] },
  )
  return render(<RouterProvider router={router} />)
}

describe('IncidentDetail', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetById.mockResolvedValue(FAKE_INCIDENT)
  })

  it('renders hostname as title', async () => {
    renderDetail()
    await waitFor(() => expect(screen.getByText('victim-host')).toBeInTheDocument())
  })

  it('renders KPI tiles', async () => {
    renderDetail()
    await waitFor(() => screen.getByText('victim-host'))
    expect(screen.getAllByText('2')).toHaveLength(2) // alert_count + MITRE count
    expect(screen.getByText('c2_beacon')).toBeInTheDocument()
  })

  it('renders MITRE tactics', async () => {
    renderDetail()
    await waitFor(() => screen.getByText('TA0011'))
    expect(screen.getByText('TA0007')).toBeInTheDocument()
  })

  it('renders timeline entry', async () => {
    renderDetail()
    await waitFor(() => screen.getByText('Suspicious network connection'))
  })

  it('shows not found for unknown id', async () => {
    mockGetById.mockRejectedValue(new Error('404'))
    renderDetail('bad-id')
    await waitFor(() => expect(screen.getByText(/introuvable/i)).toBeInTheDocument())
  })
})
