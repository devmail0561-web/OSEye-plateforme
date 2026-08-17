import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn(),
}))

import { useAuthStore } from '@/stores/authStore'
import ProtectedRoute from './ProtectedRoute'

function makeRouter(isAuthenticated: boolean) {
  const mockState = {
    accessToken: isAuthenticated ? 'test-token' : null,
    expiresAt: isAuthenticated ? Date.now() + 3600000 : null,
    isAuthenticated,
    roles: isAuthenticated ? ['analyst'] : [],
    login: vi.fn(),
    logout: vi.fn(),
    setToken: vi.fn(),
    getToken: vi.fn(() => isAuthenticated ? 'test-token' : null),
  }

  vi.mocked(useAuthStore).mockImplementation(
    (selector: any) => selector(mockState),
  )

  return createMemoryRouter([
    {
      element: <ProtectedRoute />,
      children: [{ path: '/dashboard', element: <div>Dashboard Content</div> }],
    },
    { path: '/login', element: <div>Login Page</div> },
  ], { initialEntries: ['/dashboard'] })
}

describe('ProtectedRoute', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('renders outlet when user is authenticated', () => {
    render(<RouterProvider router={makeRouter(true)} />)
    expect(screen.getByText('Dashboard Content')).toBeInTheDocument()
  })

  it('redirects to /login when user is not authenticated', () => {
    render(<RouterProvider router={makeRouter(false)} />)
    expect(screen.getByText('Login Page')).toBeInTheDocument()
    expect(screen.queryByText('Dashboard Content')).not.toBeInTheDocument()
  })
})
