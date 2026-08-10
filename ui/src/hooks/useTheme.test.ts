import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useTheme } from './useTheme'

function mockMatchMedia(matches: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockReturnValue({ matches, addEventListener: vi.fn(), removeEventListener: vi.fn() }),
  })
}

describe('useTheme', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.classList.remove('dark')
    mockMatchMedia(false)
  })

  it('reads saved dark theme from localStorage', () => {
    localStorage.setItem('oseye_theme', 'dark')
    const { result } = renderHook(() => useTheme())
    expect(result.current.isDark).toBe(true)
  })

  it('reads saved light theme from localStorage', () => {
    localStorage.setItem('oseye_theme', 'light')
    const { result } = renderHook(() => useTheme())
    expect(result.current.isDark).toBe(false)
  })

  it('falls back to system preference when no localStorage key', () => {
    mockMatchMedia(true)
    const { result } = renderHook(() => useTheme())
    expect(result.current.isDark).toBe(true)
  })

  it('adds dark class to documentElement when isDark is true', () => {
    localStorage.setItem('oseye_theme', 'dark')
    renderHook(() => useTheme())
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })

  it('toggle switches dark class on documentElement', () => {
    localStorage.setItem('oseye_theme', 'light')
    const { result } = renderHook(() => useTheme())

    expect(result.current.isDark).toBe(false)

    act(() => { result.current.toggle() })

    expect(result.current.isDark).toBe(true)
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(localStorage.getItem('oseye_theme')).toBe('dark')
  })

  it('toggle back to light removes dark class', () => {
    localStorage.setItem('oseye_theme', 'dark')
    const { result } = renderHook(() => useTheme())

    act(() => { result.current.toggle() })

    expect(result.current.isDark).toBe(false)
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    expect(localStorage.getItem('oseye_theme')).toBe('light')
  })
})
