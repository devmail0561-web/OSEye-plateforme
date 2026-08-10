import { create } from 'zustand'
import type { WSStatus } from '@/types'

interface WSState {
  status: WSStatus
  setStatus: (status: WSStatus) => void
}

export const useWSStore = create<WSState>((set) => ({
  status: 'disconnected',
  setStatus: (status) => set({ status }),
}))
