import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'

const mockSetStatus = vi.fn()

vi.mock('@/stores/wsStore', () => ({
  useWSStore: vi.fn().mockImplementation((selector: (s: { setStatus: typeof mockSetStatus }) => unknown) =>
    selector({ setStatus: mockSetStatus }),
  ),
}))

vi.mock('@/stores/authStore', () => ({
  useAuthStore: vi.fn().mockImplementation((selector: (s: { getToken: () => string }) => unknown) =>
    selector({ getToken: () => 'test-token' }),
  ),
}))

import { useWebSocket } from './useWebSocket'

const instances: MockWS[] = []

class MockWS {
  onopen: (() => void) | null = null
  onclose: (() => void) | null = null
  onmessage: ((e: { data: string }) => void) | null = null
  onerror: (() => void) | null = null
  send = vi.fn()
  close = vi.fn()

  constructor(public url: string) {
    instances.push(this)
  }
}

describe('useWebSocket', () => {
  beforeEach(() => {
    instances.length = 0
    mockSetStatus.mockClear()
    vi.useFakeTimers()
    vi.stubGlobal('WebSocket', MockWS)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('creates a WebSocket on mount', () => {
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage: vi.fn() }))
    expect(instances).toHaveLength(1)
    expect(instances[0].url).toBe('ws://test')
  })

  it('sets status to connecting on mount', () => {
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage: vi.fn() }))
    expect(mockSetStatus).toHaveBeenCalledWith('connecting')
  })

  it('sends JWT token and sets connected on open', () => {
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage: vi.fn() }))

    act(() => { instances[0].onopen?.() })

    expect(instances[0].send).toHaveBeenCalledWith('test-token')
    expect(mockSetStatus).toHaveBeenCalledWith('connected')
  })

  it('calls onMessage with parsed JSON data', () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage }))

    act(() => { instances[0].onmessage?.({ data: '{"type":"alert"}' }) })

    expect(onMessage).toHaveBeenCalledWith({ type: 'alert' })
  })

  it('ignores non-JSON frames', () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage }))

    act(() => { instances[0].onmessage?.({ data: 'ping' }) })

    expect(onMessage).not.toHaveBeenCalled()
  })

  it('sets error status on ws.onerror', () => {
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage: vi.fn() }))

    act(() => { instances[0].onerror?.() })

    expect(mockSetStatus).toHaveBeenCalledWith('error')
  })

  it('sets disconnected and schedules reconnect on close', () => {
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage: vi.fn() }))
    act(() => { instances[0].onopen?.() })
    act(() => { instances[0].onclose?.() })

    expect(mockSetStatus).toHaveBeenCalledWith('disconnected')
    expect(instances).toHaveLength(1) // no new ws yet

    act(() => { vi.advanceTimersByTime(1100) })
    expect(instances).toHaveLength(2)
  })

  it('does not connect when enabled=false', () => {
    renderHook(() => useWebSocket({ url: 'ws://test', onMessage: vi.fn(), enabled: false }))
    expect(instances).toHaveLength(0)
  })
})
