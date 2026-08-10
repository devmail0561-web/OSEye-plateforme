import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useCountdown } from './useCountdown'

describe('useCountdown', () => {
  beforeEach(() => { vi.useFakeTimers() })
  afterEach(() => { vi.useRealTimers() })

  it('returns expired=true and remaining=0 for a past date', () => {
    const past = new Date(Date.now() - 10_000).toISOString()
    const { result } = renderHook(() => useCountdown(past))
    expect(result.current.expired).toBe(true)
    expect(result.current.remaining).toBe(0)
  })

  it('returns expired=false and positive remaining for a future date', () => {
    const future = new Date(Date.now() + 60_000).toISOString()
    const { result } = renderHook(() => useCountdown(future))
    expect(result.current.expired).toBe(false)
    expect(result.current.remaining).toBeGreaterThan(0)
  })

  it('counts down as time advances', () => {
    const future = new Date(Date.now() + 5_000).toISOString()
    const { result } = renderHook(() => useCountdown(future))

    expect(result.current.remaining).toBe(5)

    act(() => { vi.advanceTimersByTime(2_000) })
    expect(result.current.remaining).toBe(3)

    act(() => { vi.advanceTimersByTime(3_000) })
    expect(result.current.remaining).toBe(0)
    expect(result.current.expired).toBe(true)
  })

  it('returns expired=true for null target', () => {
    const { result } = renderHook(() => useCountdown(null))
    expect(result.current.remaining).toBe(0)
    expect(result.current.expired).toBe(true)
  })

  it('remaining stays at 0 after target expires', () => {
    const future = new Date(Date.now() + 1_000).toISOString()
    const { result } = renderHook(() => useCountdown(future))

    act(() => { vi.advanceTimersByTime(5_000) })
    expect(result.current.remaining).toBe(0)
    expect(result.current.expired).toBe(true)
  })
})
