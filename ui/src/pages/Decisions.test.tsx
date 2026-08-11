import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

const { mockPending, mockList, mockApprove, mockReject } = vi.hoisted(() => ({
  mockPending: vi.fn(),
  mockList: vi.fn(),
  mockApprove: vi.fn(),
  mockReject: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  decisionsApi: {
    pending: mockPending,
    list: mockList,
    approve: mockApprove,
    reject: mockReject,
  },
  registerAuthCallbacks: vi.fn(),
}))

import Decisions from './Decisions'
import { useAuthStore } from '@/stores/authStore'

const BASE_DECISION = {
  decision_id: 'dec-1',
  created_at: new Date().toISOString(),
  decision_type: 'REQUEST_HUMAN' as const,
  rule_score: 0.8,
  ml_score: 0.6,
  ti_score: 0.5,
  correlation_depth: 2,
  final_score: 0.7,
  entity_id: 'host-a',
  trigger_alert_id: 'alert-1',
  incident_chain_id: null,
  related_event_ids: [],
  policy_version: 'v1',
  explanation: 'High risk lateral movement detected',
  requires_human: true,
  human_decision: null,
  human_operator: null,
  human_note: null,
  approved_at: null,
  timeout_at: new Date(Date.now() + 300_000).toISOString(),
  prev_journal_hash: 'h0',
  journal_hash: 'h1',
}

function renderDecisions() {
  return render(<MemoryRouter><Decisions /></MemoryRouter>)
}

describe('Decisions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useAuthStore.setState({ roles: ['admin', 'analyst'] })
    mockPending.mockResolvedValue([BASE_DECISION])
    mockList.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 })
    mockApprove.mockResolvedValue({ ...BASE_DECISION, human_decision: 'approved' })
    mockReject.mockResolvedValue({ ...BASE_DECISION, human_decision: 'rejected' })
  })

  it('shows pending decision card with explanation', async () => {
    renderDecisions()
    await waitFor(() =>
      expect(screen.getByText('High risk lateral movement detected')).toBeInTheDocument(),
    )
  })

  it('calls approve API and removes card from pending', async () => {
    const user = userEvent.setup()
    renderDecisions()

    await waitFor(() => screen.getByText('High risk lateral movement detected'))
    await user.click(screen.getByRole('button', { name: /approuver/i }))

    await waitFor(() => expect(mockApprove).toHaveBeenCalledWith('dec-1', ''))
    expect(screen.queryByText('High risk lateral movement detected')).not.toBeInTheDocument()
  })

  it('calls reject API and removes card from pending', async () => {
    const user = userEvent.setup()
    renderDecisions()

    await waitFor(() => screen.getByText('High risk lateral movement detected'))
    await user.click(screen.getByRole('button', { name: /rejeter/i }))

    await waitFor(() => expect(mockReject).toHaveBeenCalledWith('dec-1', ''))
    expect(screen.queryByText('High risk lateral movement detected')).not.toBeInTheDocument()
  })

  it('passes note text to approve call', async () => {
    const user = userEvent.setup()
    renderDecisions()

    await waitFor(() => screen.getByText('High risk lateral movement detected'))
    await user.type(screen.getByPlaceholderText(/note/i), 'reviewed OK')
    await user.click(screen.getByRole('button', { name: /approuver/i }))

    await waitFor(() => expect(mockApprove).toHaveBeenCalledWith('dec-1', 'reviewed OK'))
  })

  it('shows no pending section when no pending decisions', async () => {
    mockPending.mockResolvedValue([])
    renderDecisions()
    await waitFor(() => expect(mockPending).toHaveBeenCalled())
    expect(screen.queryByText(/en attente d'approbation/i)).not.toBeInTheDocument()
  })
})
