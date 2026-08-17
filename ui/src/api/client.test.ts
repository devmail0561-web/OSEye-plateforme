import { beforeAll, afterAll, afterEach, describe, it, expect, vi } from 'vitest'
import { setupServer } from 'msw/node'
import { http, HttpResponse } from 'msw'

let capturedAuth: string | null = null

const server = setupServer(
  http.get('*/api/v1/health', ({ request }) => {
    capturedAuth = request.headers.get('authorization')
    return HttpResponse.json({ status: 'ok', service: 'test' })
  }),
  http.post('*/api/v1/auth/token', async () => {
    return HttpResponse.json({ access_token: 'fresh', token_type: 'bearer' })
  }),
)

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }))
afterEach(() => {
  server.resetHandlers()
  capturedAuth = null
  vi.clearAllMocks()
})
afterAll(() => server.close())

import { registerAuthCallbacks, healthApi, authApi } from './client'

describe('API client — token injection', () => {
  it('injects Bearer token when getToken returns a value', async () => {
    registerAuthCallbacks(() => 'my-test-token', vi.fn())
    await healthApi.check()
    expect(capturedAuth).toBe('Bearer my-test-token')
  })

  it('sends no Authorization header when getToken returns null', async () => {
    registerAuthCallbacks(() => null, vi.fn())
    await healthApi.check()
    expect(capturedAuth).toBeNull()
  })

  it('updates injected token when callback changes', async () => {
    registerAuthCallbacks(() => 'token-v1', vi.fn())
    await healthApi.check()
    expect(capturedAuth).toBe('Bearer token-v1')

    registerAuthCallbacks(() => 'token-v2', vi.fn())
    await healthApi.check()
    expect(capturedAuth).toBe('Bearer token-v2')
  })
})

describe('API client — authApi', () => {
  it('posts form-encoded credentials to /auth/token', async () => {
    const result = await authApi.login('admin', 'secret')
    expect(result.access_token).toBe('fresh')
  })
})
