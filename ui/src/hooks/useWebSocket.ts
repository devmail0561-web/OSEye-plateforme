import { useEffect, useRef, useCallback } from 'react'
import { useWSStore } from '@/stores/wsStore'
import { useAuthStore } from '@/stores/authStore'

export interface UseWebSocketOptions {
  url: string
  onMessage: (data: unknown) => void
  enabled?: boolean
}

const MAX_BACKOFF = 30_000

export function useWebSocket({ url, onMessage, enabled = true }: UseWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null)
  const backoffRef = useRef(1000)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const setStatus = useWSStore((s) => s.setStatus)
  const getToken = useAuthStore((s) => s.getToken)

  const disconnect = useCallback(() => {
    if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }
    setStatus('disconnected')
  }, [setStatus])

  const connect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.close()
    }

    setStatus('connecting')
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      backoffRef.current = 1000
      setStatus('connected')
      const token = getToken()
      if (token) ws.send(token)
    }

    ws.onmessage = (event) => {
      try {
        const data: unknown = JSON.parse(event.data as string)
        onMessage(data)
      } catch {
        // ignore non-JSON frames (e.g. server ping "ping")
      }
    }

    ws.onerror = () => {
      setStatus('error')
    }

    ws.onclose = () => {
      wsRef.current = null
      setStatus('disconnected')
      reconnectTimerRef.current = setTimeout(() => {
        backoffRef.current = Math.min(backoffRef.current * 2, MAX_BACKOFF)
        connect()
      }, backoffRef.current)
    }
  }, [url, onMessage, setStatus, getToken]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!enabled) {
      disconnect()
      return
    }
    connect()
    return disconnect
  }, [enabled, connect, disconnect])

  return { disconnect }
}
