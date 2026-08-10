import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

const { mockList, mockValidate, mockReload } = vi.hoisted(() => ({
  mockList: vi.fn(),
  mockValidate: vi.fn(),
  mockReload: vi.fn(),
}))

vi.mock('@/api/client', () => ({
  rulesApi: { list: mockList, validate: mockValidate, reload: mockReload },
}))

vi.mock('@/hooks/useTheme', () => ({
  useTheme: () => ({ isDark: true, toggle: vi.fn() }),
}))

vi.mock('@/components/CodeEditor', () => ({
  default: ({ value, onChange }: { value: string; onChange?: (v: string) => void }) => (
    <textarea
      data-testid="code-editor"
      value={value}
      onChange={(e) => onChange?.(e.target.value)}
    />
  ),
}))

import Rules from './Rules'

const FAKE_RULE = {
  id: 'rule-1',
  name: 'detect.lateral_movement',
  enabled: true,
  severity: 'high' as const,
  condition_yaml: 'event.type: connect',
  timeframe: 60,
  actions: ['alert'],
  tags: ['network', 'lateral'],
  mitre: ['T1021'],
  explanation: 'Detects lateral movement',
  match_count: 42,
  last_matched: new Date().toISOString(),
  false_positive_count: 1,
  source: 'builtin' as const,
}

function renderRules() {
  return render(<MemoryRouter><Rules /></MemoryRouter>)
}

describe('Rules', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockList.mockResolvedValue({ items: [FAKE_RULE], total: 1 })
    mockValidate.mockResolvedValue({ valid: true, error: null })
    mockReload.mockResolvedValue({ reloaded: 1 })
  })

  it('renders rule name', async () => {
    renderRules()
    await waitFor(() => expect(screen.getByText('detect.lateral_movement')).toBeInTheDocument())
  })

  it('renders enabled dot (green)', async () => {
    renderRules()
    await waitFor(() => screen.getByText('detect.lateral_movement'))
    const dot = document.querySelector('.bg-green-400')
    expect(dot).toBeInTheDocument()
  })

  it('expands rule row to show detail on click', async () => {
    const user = userEvent.setup()
    renderRules()

    await waitFor(() => screen.getByText('detect.lateral_movement'))
    await user.click(screen.getByText('detect.lateral_movement').closest('tr')!)

    expect(screen.getByTestId('code-editor')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /valider/i })).toBeInTheDocument()
  })

  it('shows valid feedback after validation', async () => {
    const user = userEvent.setup()
    renderRules()

    await waitFor(() => screen.getByText('detect.lateral_movement'))
    await user.click(screen.getByText('detect.lateral_movement').closest('tr')!)
    await user.click(screen.getByRole('button', { name: /valider/i }))

    await waitFor(() => expect(screen.getByText(/syntaxe valide/i)).toBeInTheDocument())
  })

  it('shows error feedback when validation fails', async () => {
    mockValidate.mockResolvedValue({ valid: false, error: 'unexpected token' })
    const user = userEvent.setup()
    renderRules()

    await waitFor(() => screen.getByText('detect.lateral_movement'))
    await user.click(screen.getByText('detect.lateral_movement').closest('tr')!)
    await user.click(screen.getByRole('button', { name: /valider/i }))

    await waitFor(() => expect(screen.getByText('unexpected token')).toBeInTheDocument())
  })

  it('calls reload and shows success message', async () => {
    const user = userEvent.setup()
    renderRules()

    await waitFor(() => screen.getByText('detect.lateral_movement'))
    await user.click(screen.getByRole('button', { name: /recharger/i }))

    await waitFor(() => expect(mockReload).toHaveBeenCalled())
    expect(screen.getByText(/1 règle\(s\) rechargée\(s\)/i)).toBeInTheDocument()
  })
})
