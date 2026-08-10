import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

const { mockList, mockCreate } = vi.hoisted(() => ({
  mockList: vi.fn(),
  mockCreate: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  casesApi: { list: mockList, create: mockCreate },
}))

import Cases from './Cases'

const FAKE_CASE = {
  case_id: 'case-1',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  title: 'Ransomware investigation',
  description: 'Encrypted files detected',
  severity: 'critical' as const,
  status: 'open' as const,
  tags: ['ransomware'],
  assigned_to: null,
  created_by: 'analyst1',
  event_ids: [],
  alert_ids: ['a1', 'a2'],
  evidence: [],
  notes: [],
  custody_log: [],
}

function renderCases() {
  return render(<MemoryRouter><Cases /></MemoryRouter>)
}

describe('Cases', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockList.mockResolvedValue({ items: [FAKE_CASE], total: 1, limit: 25, offset: 0 })
  })

  it('renders case rows with title', async () => {
    renderCases()
    await waitFor(() => expect(screen.getByText('Ransomware investigation')).toBeInTheDocument())
  })

  it('renders alert count', async () => {
    renderCases()
    await waitFor(() => screen.getByText('Ransomware investigation'))
    expect(screen.getByText('2')).toBeInTheDocument()
  })

  it('renders tags', async () => {
    renderCases()
    await waitFor(() => screen.getByText('ransomware'))
  })

  it('shows empty state when no cases', async () => {
    mockList.mockResolvedValue({ items: [], total: 0, limit: 25, offset: 0 })
    renderCases()
    await waitFor(() => expect(screen.getByText(/aucun cas/i)).toBeInTheDocument())
  })

  it('opens and closes the new case modal', async () => {
    const user = userEvent.setup()
    renderCases()

    await waitFor(() => screen.getByText('Ransomware investigation'))
    await user.click(screen.getByRole('button', { name: /nouveau cas/i }))
    expect(screen.getByText(/nouveau cas/i, { selector: 'h2' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /annuler/i }))
    expect(screen.queryByRole('button', { name: /annuler/i })).not.toBeInTheDocument()
  })

  it('creates a case via the modal and adds it to the list', async () => {
    const newCase = { ...FAKE_CASE, case_id: 'case-2', title: 'New case' }
    mockCreate.mockResolvedValue(newCase)
    const user = userEvent.setup()
    renderCases()

    await waitFor(() => screen.getByText('Ransomware investigation'))
    await user.click(screen.getByRole('button', { name: /nouveau cas/i }))
    await user.type(screen.getByPlaceholderText(/titre/i), 'New case')
    await user.click(screen.getByRole('button', { name: /créer/i }))

    await waitFor(() => expect(mockCreate).toHaveBeenCalled())
    expect(mockCreate).toHaveBeenCalledWith(expect.objectContaining({ title: 'New case' }))
  })
})
