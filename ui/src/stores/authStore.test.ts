import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@/api/client', () => ({
  authApi: { login: vi.fn() },
  registerAuthCallbacks: vi.fn(),
}))

import { useAuthStore } from './authStore'
import { authApi } from '@/api/client'

const FAKE_PAYLOAD = btoa(JSON.stringify({ exp: 9_999_999_999 }))
const FAKE_TOKEN = `header.${FAKE_PAYLOAD}.sig`

describe('authStore', () => {
  beforeEach(() => {
    localStorage.clear()
    useAuthStore.setState({ accessToken: null, expiresAt: null, isAuthenticated: false })
    vi.clearAllMocks()
  })

  it('login stores token and marks authenticated', async () => {
    vi.mocked(authApi.login).mockResolvedValue({ access_token: FAKE_TOKEN, token_type: 'bearer' })

    await useAuthStore.getState().login('user', 'pass')

    expect(useAuthStore.getState().isAuthenticated).toBe(true)
    expect(useAuthStore.getState().accessToken).toBe(FAKE_TOKEN)
    expect(localStorage.getItem('oseye_token')).toBe(FAKE_TOKEN)
  })

  it('login decodes exp from JWT payload', async () => {
    vi.mocked(authApi.login).mockResolvedValue({ access_token: FAKE_TOKEN, token_type: 'bearer' })

    await useAuthStore.getState().login('user', 'pass')

    expect(useAuthStore.getState().expiresAt).toBe(9_999_999_999 * 1000)
  })

  it('logout clears state and localStorage', () => {
    localStorage.setItem('oseye_token', FAKE_TOKEN)
    useAuthStore.setState({ accessToken: FAKE_TOKEN, isAuthenticated: true })

    useAuthStore.getState().logout()

    expect(useAuthStore.getState().isAuthenticated).toBe(false)
    expect(useAuthStore.getState().accessToken).toBeNull()
    expect(localStorage.getItem('oseye_token')).toBeNull()
  })

  it('setToken stores token and marks authenticated', () => {
    useAuthStore.getState().setToken(FAKE_TOKEN)

    expect(useAuthStore.getState().accessToken).toBe(FAKE_TOKEN)
    expect(useAuthStore.getState().isAuthenticated).toBe(true)
    expect(localStorage.getItem('oseye_token')).toBe(FAKE_TOKEN)
  })

  it('getToken returns current access token', () => {
    useAuthStore.setState({ accessToken: 'abc' })
    expect(useAuthStore.getState().getToken()).toBe('abc')
  })

  it('getToken returns null when no token', () => {
    useAuthStore.setState({ accessToken: null })
    expect(useAuthStore.getState().getToken()).toBeNull()
  })
})
