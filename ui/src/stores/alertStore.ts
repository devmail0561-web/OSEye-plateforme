import { create } from 'zustand'
import type { Alert, AlertStats } from '@/types'
import { alertsApi } from '@/api/client'

interface AlertStoreState {
  alerts: Alert[]
  stats: AlertStats | null
  openCount: number
  isLoading: boolean
  fetchAlerts: (params?: { limit?: number; offset?: number }) => Promise<void>
  fetchStats: () => Promise<void>
  appendAlert: (alert: Alert) => void
  updateAlert: (alert: Alert) => void
}

export const useAlertStore = create<AlertStoreState>((set, get) => ({
  alerts: [],
  stats: null,
  openCount: 0,
  isLoading: false,

  fetchAlerts: async (params = {}) => {
    set({ isLoading: true })
    try {
      const data = await alertsApi.list(params)
      set({ alerts: data.items })
    } finally {
      set({ isLoading: false })
    }
  },

  fetchStats: async () => {
    try {
      const data = await alertsApi.stats()
      // Vérifier que data est bien un objet AlertStats valide
      if (data && typeof data.open === 'number' && data.by_severity) {
        set({ stats: data, openCount: data.open })
      }
    } catch (err) {
      // Ignorer les erreurs (non authentifié, réseau, etc.)
      console.warn('fetchStats failed:', err)
    }
  },

  appendAlert: (alert) => {
    const current = get().alerts
    set({ alerts: [alert, ...current] })
    if (alert.status === 'open') {
      set((s) => ({ openCount: s.openCount + 1 }))
    }
  },

  updateAlert: (updated) => {
    set((s) => ({
      alerts: s.alerts.map((a) => (a.alert_id === updated.alert_id ? updated : a)),
    }))
  },
}))
