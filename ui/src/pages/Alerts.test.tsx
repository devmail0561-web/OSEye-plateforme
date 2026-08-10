import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

const { mockList, mockAck, mockFP } = vi.hoisted(() => ({
  mockList: vi.fn(),
  mockAck: vi.fn(),
  mockFP: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  alertsApi: { list: mockList, acknowledge: mockAck, falsePositive: mockFP },
}))

vi.mock('@/stores/alertStore', () => ({
  useAlertStore: Object.assign(
    vi.fn().mockReturnValue(vi.fn()),
    { getState: () => ({ alerts: [] }) },
  ),
}))

import Alerts from './Alerts'

const FAKE_ALERT = {
  alert_id: 'alert-1',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  severity: 'high' as const,
  status: 'open' as const,
  rule_id: null,
  ml_triggered: false,
  ti_triggered: false,
  entity_id: 'entity-1',
  hostname: 'victim-host',
  trigger_event_id: 'evt-1',
  related_event_ids: [],
  incident_chain_id: null,
  title: 'Suspicious process',
  description: 'proc launched by init',
  mitre_techniques: ['T1059'],
  assigned_to: null,
  notes: [],
  false_positive_count: 0,
}

function renderAlerts() {
  return render(<MemoryRouter><Alerts /></MemoryRouter>)
}

describe('Alerts', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockList.mockResolvedValue({ items: [FAKE_ALERT], total: 1, limit: 50, offset: 0 })
  })

  it('renders alert rows after loading', async () => {
    renderAlerts()
    await waitFor(() => expect(screen.getByText('Suspicious process')).toBeInTheDocument())
    expect(screen.getByText('victim-host')).toBeInTheDocument()
  })

  it('shows Acquitter button for open alerts', async () => {
    renderAlerts()
    await waitFor(() => screen.getByText('Suspicious process'))
    expect(screen.getByRole('button', { name: /acquitter/i })).toBeInTheDocument()
  })

  it('calls acknowledge API on Acquitter click', async () => {
    mockAck.mockResolvedValue({ ...FAKE_ALERT, status: 'acknowledged' as const })
    const user = userEvent.setup()
    renderAlerts()

    await waitFor(() => screen.getByText('Suspicious process'))
    await user.click(screen.getByRole('button', { name: /acquitter/i }))

    await waitFor(() => expect(mockAck).toHaveBeenCalledWith('alert-1'))
  })

  it('calls falsePositive API on FP click', async () => {
    mockFP.mockResolvedValue({ ...FAKE_ALERT, status: 'false_positive' as const })
    const user = userEvent.setup()
    renderAlerts()

    await waitFor(() => screen.getByText('Suspicious process'))
    await user.click(screen.getByRole('button', { name: /^fp$/i }))

    await waitFor(() => expect(mockFP).toHaveBeenCalledWith('alert-1'))
  })

  it('shows total count after load', async () => {
    renderAlerts()
    await waitFor(() => screen.getByText('Suspicious process'))
    expect(screen.getByText(/1 alertes au total/i)).toBeInTheDocument()
  })

  it('shows empty state when no alerts', async () => {
    mockList.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 })
    renderAlerts()
    await waitFor(() => expect(screen.getByText(/aucune alerte/i)).toBeInTheDocument())
  })
})
