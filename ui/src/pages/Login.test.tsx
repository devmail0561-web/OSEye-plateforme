import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'

const mockLogin = vi.fn()
const mockNavigate = vi.fn()

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn((selector: (s: { login: typeof mockLogin }) => unknown) =>
    selector({ login: mockLogin }),
  ),
}))

vi.mock('react-router-dom', async (importActual) => {
  const actual = await importActual<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

import Login from './Login'

function renderLogin() {
  const router = createMemoryRouter([{ path: '/', element: <Login /> }], {
    initialEntries: ['/'],
  })
  return render(<RouterProvider router={router} />)
}

describe('Login', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders username and password fields', () => {
    renderLogin()
    expect(screen.getByLabelText(/utilisateur/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/mot de passe/i)).toBeInTheDocument()
  })

  it('submits credentials and navigates to /dashboard on success', async () => {
    mockLogin.mockResolvedValue(undefined)
    const user = userEvent.setup()
    renderLogin()

    await user.type(screen.getByLabelText(/utilisateur/i), 'admin')
    await user.type(screen.getByLabelText(/mot de passe/i), 'secret')
    await user.click(screen.getByRole('button', { name: /se connecter/i }))

    await waitFor(() => expect(mockLogin).toHaveBeenCalledWith('admin', 'secret'))
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard', { replace: true })
  })

  it('shows error message on failed login', async () => {
    mockLogin.mockRejectedValue(new Error('401'))
    const user = userEvent.setup()
    renderLogin()

    await user.type(screen.getByLabelText(/utilisateur/i), 'bad')
    await user.type(screen.getByLabelText(/mot de passe/i), 'wrong')
    await user.click(screen.getByRole('button', { name: /se connecter/i }))

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Identifiants invalides'),
    )
    expect(mockNavigate).not.toHaveBeenCalled()
  })

  it('disables submit button while loading', async () => {
    let resolve: () => void
    mockLogin.mockReturnValue(new Promise<void>((r) => { resolve = r }))
    const user = userEvent.setup()
    renderLogin()

    await user.type(screen.getByLabelText(/utilisateur/i), 'u')
    await user.type(screen.getByLabelText(/mot de passe/i), 'p')
    await user.click(screen.getByRole('button', { name: /se connecter/i }))

    expect(screen.getByRole('button')).toBeDisabled()
    resolve!()
    await waitFor(() => expect(screen.getByRole('button')).not.toBeDisabled())
  })
})
