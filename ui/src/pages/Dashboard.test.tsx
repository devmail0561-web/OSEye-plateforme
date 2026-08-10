import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const { mockFetchStats } = vi.hoisted(() => ({ mockFetchStats: vi.fn() }))

vi.mock('@/stores/alertStore', () => ({
  useAlertStore: vi.fn().mockReturnValue({
    fetchStats: mockFetchStats,
    stats: { by_severity: { low: 1, medium: 2, high: 3, critical: 4 }, open: 10 },
    openCount: 10,
  }),
}))

vi.mock('@/stores/eventStore', () => ({
  useEventStore: vi.fn().mockReturnValue({
    rateHistory: [],
    eventsPerSecond: 42,
  }),
}))

vi.mock('@/hooks/useAlertsWebSocket', () => ({
  useAlertsWebSocket: vi.fn(),
}))

vi.mock('@/hooks/useTheme', () => ({
  useTheme: () => ({ isDark: true, toggle: vi.fn() }),
}))

vi.mock('recharts', () => ({
  LineChart: () => <div data-testid="line-chart" />,
  Line: () => null,
  XAxis: () => null,
  YAxis: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  PieChart: () => <div data-testid="pie-chart" />,
  Pie: () => null,
  Cell: () => null,
}))

import Dashboard from './Dashboard'

function renderDashboard() {
  return render(<MemoryRouter><Dashboard /></MemoryRouter>)
}

describe('Dashboard', () => {
  beforeEach(() => {
    mockFetchStats.mockResolvedValue(undefined)
    vi.clearAllMocks()
    mockFetchStats.mockResolvedValue(undefined)
  })

  it('renders the open alert count KPI tile', () => {
    renderDashboard()
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText(/alertes ouvertes/i)).toBeInTheDocument()
  })

  it('renders the events/s KPI tile', () => {
    renderDashboard()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText(/événements\/s/i)).toBeInTheDocument()
  })

  it('calls fetchStats on mount', async () => {
    renderDashboard()
    await waitFor(() => expect(mockFetchStats).toHaveBeenCalledTimes(1))
  })

  it('renders a link to /alerts?status=open from the KPI tile', () => {
    renderDashboard()
    const link = screen.getByRole('link', { name: /alertes ouvertes/i })
    expect(link).toHaveAttribute('href', '/alerts?status=open')
  })
})
