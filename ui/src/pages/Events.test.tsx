import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

const { mockList } = vi.hoisted(() => ({ mockList: vi.fn() }))

vi.mock('@/api/client', () => ({
  eventsApi: { list: mockList },
}))

import Events from './Events'

const FAKE_EVENT = {
  event_id: 'evt-1',
  timestamp_ns: Date.now() * 1_000_000,
  hostname: 'server-01',
  agent_id: 'ag-1',
  category: 'network',
  type: 'connect',
  severity: 'medium',
  collector: 'ebpf',
  os: 'linux',
  uid: 0, gid: 0, pid: 100, ppid: 1,
  process_name: 'nginx',
  executable: '/usr/sbin/nginx',
  cmdline: 'nginx -g daemon off',
  cwd: '/',
  session_id: null,
  resource: '10.0.0.1:80',
  result: 'success',
  file_hash_before: null, file_hash_after: null,
  src_ip: null, src_port: null, dst_ip: '10.0.0.1', dst_port: 80,
  protocol: 'TCP', bytes_sent: null, bytes_recv: null,
  hash_chain: 'abc', signature: null, ml_score: null, risk_score: null,
  rule_match_ids: [], mitre_techniques: [], ti_tags: [],
  incident_chain_id: null, extra: {},
}

function renderEvents(search = '') {
  return render(
    <MemoryRouter initialEntries={[`/events${search}`]}>
      <Events />
    </MemoryRouter>,
  )
}

describe('Events', () => {
  beforeEach(() => {
    mockList.mockResolvedValue({ items: [FAKE_EVENT], total: 1, limit: 50, offset: 0 })
  })

  it('renders event rows after loading', async () => {
    renderEvents()
    await waitFor(() => expect(screen.getByText('server-01')).toBeInTheDocument())
    expect(screen.getByText('nginx')).toBeInTheDocument()
  })

  it('shows loading state initially', () => {
    mockList.mockReturnValue(new Promise(() => {}))
    renderEvents()
    expect(screen.getByText(/chargement/i)).toBeInTheDocument()
  })

  it('shows empty state when no events', async () => {
    mockList.mockResolvedValue({ items: [], total: 0, limit: 50, offset: 0 })
    renderEvents()
    await waitFor(() => expect(screen.getByText(/aucun événement/i)).toBeInTheDocument())
  })

  it('calls list with category filter from URL', async () => {
    renderEvents('?category=network')
    await waitFor(() => expect(mockList).toHaveBeenCalled())
    expect(mockList).toHaveBeenCalledWith(expect.objectContaining({ category: 'network' }))
  })

  it('expands row to show JSON on click', async () => {
    const user = userEvent.setup()
    renderEvents()
    await waitFor(() => screen.getByText('server-01'))
    await user.click(screen.getByText('server-01').closest('tr')!)
    expect(screen.getByText(/event_id/)).toBeInTheDocument()
  })

  it('disables Préc. button on first page', async () => {
    renderEvents()
    await waitFor(() => screen.getByText('server-01'))
    const prevBtn = screen.getByRole('button', { name: /préc/i })
    expect(prevBtn).toBeDisabled()
  })
})
