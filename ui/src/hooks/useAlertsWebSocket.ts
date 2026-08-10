import { useCallback } from 'react'
import { useWebSocket } from './useWebSocket'
import { useAlertStore } from '@/stores/alertStore'
import { useEventStore } from '@/stores/eventStore'
import type { Alert, UniversalEvent } from '@/types'

function isAlert(data: unknown): data is Alert {
  return (
    typeof data === 'object' &&
    data !== null &&
    'alert_id' in data &&
    'severity' in data
  )
}

function isEvent(data: unknown): data is UniversalEvent {
  return (
    typeof data === 'object' &&
    data !== null &&
    'event_id' in data &&
    'timestamp_ns' in data
  )
}

export function useAlertsWebSocket(enabled = true) {
  const appendAlert = useAlertStore((s) => s.appendAlert)
  const pushEvent = useEventStore((s) => s.pushEvent)

  const onMessage = useCallback(
    (data: unknown) => {
      if (isAlert(data)) appendAlert(data)
      else if (isEvent(data)) pushEvent(data)
    },
    [appendAlert, pushEvent],
  )

  // M-4: derive scheme from page protocol so wss:// is used automatically in
  // production (HTTPS) without requiring an explicit VITE_WS_URL override.
  const defaultWsUrl = (() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${proto}//${window.location.host}/ws/alerts`
  })()
  const wsUrl = import.meta.env.VITE_WS_URL
    ? `${import.meta.env.VITE_WS_URL}/ws/alerts`
    : defaultWsUrl

  return useWebSocket({ url: wsUrl, onMessage, enabled })
}
