import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'

const { mockGetById, mockAddNote, mockAddEvidence, mockClose, mockPatch } = vi.hoisted(() => ({
  mockGetById: vi.fn(),
  mockAddNote: vi.fn(),
  mockAddEvidence: vi.fn(),
  mockClose: vi.fn(),
  mockPatch: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  casesApi: {
    getById: mockGetById,
    addNote: mockAddNote,
    addEvidence: mockAddEvidence,
    close: mockClose,
    patch: mockPatch,
    exportJson: vi.fn().mockResolvedValue(new Blob()),
    exportHtml: vi.fn().mockResolvedValue(new Blob()),
    exportPdf: vi.fn().mockResolvedValue(new Blob()),
  },
}))

import CaseDetail from './CaseDetail'

const FAKE_CASE = {
  case_id: 'case-1',
  created_at: new Date().toISOString(),
  updated_at: new Date().toISOString(),
  title: 'APT Investigation',
  description: 'Nation-state actor',
  severity: 'critical' as const,
  status: 'open' as const,
  tags: [],
  assigned_to: null,
  created_by: 'analyst1',
  event_ids: [],
  alert_ids: [],
  evidence: [],
  notes: [],
  custody_log: [],
}

function renderDetail(id = 'case-1') {
  const router = createMemoryRouter(
    [{ path: '/cases/:id', element: <CaseDetail /> }],
    { initialEntries: [`/cases/${id}`] },
  )
  return render(<RouterProvider router={router} />)
}

describe('CaseDetail', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetById.mockResolvedValue(FAKE_CASE)
    mockAddNote.mockResolvedValue({
      note_id: 'n1', case_id: 'case-1', created_at: new Date().toISOString(),
      updated_at: null, author: 'analyst1', content: 'test note',
    })
    mockAddEvidence.mockResolvedValue({
      evidence_id: 'ev1', type: 'note', content: 'hash123', description: null,
      added_by: 'analyst1', added_at: new Date().toISOString(),
      marked_as_evidence_at: new Date().toISOString(),
    })
  })

  it('renders case title', async () => {
    renderDetail()
    await waitFor(() => expect(screen.getByText('APT Investigation')).toBeInTheDocument())
  })

  it('renders the 5 tabs', async () => {
    renderDetail()
    await waitFor(() => screen.getByText('APT Investigation'))
    for (const tab of ['Aperçu', 'Preuves', 'Notes', 'Custody', 'Timeline']) {
      expect(screen.getByRole('button', { name: tab })).toBeInTheDocument()
    }
  })

  it('adds a note via the Notes tab', async () => {
    const user = userEvent.setup()
    renderDetail()

    await waitFor(() => screen.getByText('APT Investigation'))
    await user.click(screen.getByRole('button', { name: 'Notes' }))
    await user.type(screen.getByPlaceholderText(/ajouter une note/i), 'test note')
    await user.click(screen.getByRole('button', { name: /publier/i }))

    await waitFor(() => expect(mockAddNote).toHaveBeenCalledWith('case-1', 'test note'))
  })

  it('adds evidence via the Preuves tab', async () => {
    const user = userEvent.setup()
    renderDetail()

    await waitFor(() => screen.getByText('APT Investigation'))
    await user.click(screen.getByRole('button', { name: 'Preuves' }))
    await user.type(screen.getByPlaceholderText(/contenu/i), 'hash123')
    await user.click(screen.getByRole('button', { name: /ajouter/i }))

    await waitFor(() => expect(mockAddEvidence).toHaveBeenCalledWith('case-1',
      expect.objectContaining({ content: 'hash123' }),
    ))
  })

  it('shows close form in Aperçu tab', async () => {
    renderDetail()
    await waitFor(() => screen.getByText('APT Investigation'))
    expect(screen.getByRole('button', { name: /clôturer/i })).toBeInTheDocument()
  })
})
