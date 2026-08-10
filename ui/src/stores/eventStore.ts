import { create } from 'zustand'
import type { UniversalEvent } from '@/types'

const WINDOW_S = 60
const MAX_RECENT = 500

interface RatePoint {
  ts: number
  rps: number
}

interface EventStoreState {
  recentEvents: UniversalEvent[]
  rateHistory: RatePoint[]
  eventsPerSecond: number
  pushEvent: (event: UniversalEvent) => void
  tickRate: () => void
}

// Sliding window event bucket (1s granularity)
const buckets = new Map<number, number>()

export const useEventStore = create<EventStoreState>((set) => ({
  recentEvents: [],
  rateHistory: [],
  eventsPerSecond: 0,

  pushEvent: (event) => {
    const bucket = Math.floor(Date.now() / 1000)
    buckets.set(bucket, (buckets.get(bucket) ?? 0) + 1)
    set((s) => ({
      recentEvents: [event, ...s.recentEvents].slice(0, MAX_RECENT),
    }))
  },

  tickRate: () => {
    const now = Math.floor(Date.now() / 1000)
    const cutoff = now - WINDOW_S
    for (const key of buckets.keys()) {
      if (key < cutoff) buckets.delete(key)
    }
    const history: RatePoint[] = []
    for (let t = now - WINDOW_S + 1; t <= now; t++) {
      history.push({ ts: t, rps: buckets.get(t) ?? 0 })
    }
    const current = buckets.get(now) ?? 0
    set({ rateHistory: history, eventsPerSecond: current })
  },
}))

// Tick the rate computation every second
setInterval(() => {
  useEventStore.getState().tickRate()
}, 1000)
