import { create } from 'zustand'
import { authApi, registerAuthCallbacks } from '@/api/client'

const TOKEN_KEY = 'oseye_token'
const EXPIRES_KEY = 'oseye_expires'

function decodeExpiry(token: string): number | null {
  try {
    const payload = token.split('.')[1]
    if (!payload) return null
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as {
      exp?: number
    }
    return decoded.exp ? decoded.exp * 1000 : null
  } catch {
    return null
  }
}

function decodeRoles(token: string): string[] {
  try {
    const payload = token.split('.')[1]
    if (!payload) return []
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as {
      roles?: string[]
    }
    return Array.isArray(decoded.roles) ? decoded.roles : []
  } catch {
    return []
  }
}

function initialRoles(): string[] {
  const token = localStorage.getItem(TOKEN_KEY)
  const expires = Number(localStorage.getItem(EXPIRES_KEY)) || 0
  if (!token || expires <= Date.now()) return []
  return decodeRoles(token)
}

interface AuthState {
  accessToken: string | null
  expiresAt: number | null
  isAuthenticated: boolean
  roles: string[]
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  setToken: (token: string) => void
  getToken: () => string | null
}

export const useAuthStore = create<AuthState>((set, get) => ({
  accessToken: localStorage.getItem(TOKEN_KEY),
  expiresAt: Number(localStorage.getItem(EXPIRES_KEY)) || null,
  // M-3: check both token presence AND expiry so an expired token is not
  // treated as authenticated (guards ProtectedRoute on page reload).
  isAuthenticated:
    !!localStorage.getItem(TOKEN_KEY) &&
    (Number(localStorage.getItem(EXPIRES_KEY)) || 0) > Date.now(),
  roles: initialRoles(),

  login: async (username, password) => {
    const data = await authApi.login(username, password)
    const expiresAt = decodeExpiry(data.access_token)
    const roles = decodeRoles(data.access_token)
    localStorage.setItem(TOKEN_KEY, data.access_token)
    if (expiresAt) localStorage.setItem(EXPIRES_KEY, String(expiresAt))
    set({ accessToken: data.access_token, expiresAt, isAuthenticated: true, roles })
  },

  logout: () => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(EXPIRES_KEY)
    set({ accessToken: null, expiresAt: null, isAuthenticated: false, roles: [] })
  },

  setToken: (token: string) => {
    const expiresAt = decodeExpiry(token)
    const roles = decodeRoles(token)
    localStorage.setItem(TOKEN_KEY, token)
    if (expiresAt) localStorage.setItem(EXPIRES_KEY, String(expiresAt))
    set({ accessToken: token, expiresAt, isAuthenticated: true, roles })
  },

  getToken: () => get().accessToken,
}))

// Register callbacks for the API client interceptor
registerAuthCallbacks(
  () => useAuthStore.getState().getToken(),
  () => useAuthStore.getState().logout(),
)
