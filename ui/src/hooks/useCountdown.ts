import { useState, useEffect, useRef } from 'react'

export function useCountdown(targetISO: string | null): { remaining: number; expired: boolean } {
  const getRemaining = () => {
    if (!targetISO) return 0
    return Math.max(0, Math.floor((new Date(targetISO).getTime() - Date.now()) / 1000))
  }

  const [remaining, setRemaining] = useState(getRemaining)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (!targetISO) return

    setRemaining(getRemaining())

    intervalRef.current = setInterval(() => {
      const r = getRemaining()
      setRemaining(r)
      if (r <= 0 && intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }, 1000)

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [targetISO]) // eslint-disable-line react-hooks/exhaustive-deps

  return { remaining, expired: remaining <= 0 }
}
