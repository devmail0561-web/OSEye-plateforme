import React, { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { List } from 'lucide-react'
import { eventsApi, type EventQueryParams } from '@/api/client'
import type { UniversalEvent } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'
import { EmptyState, Spinner, Input, Select } from '@/components/ui'

const CATEGORIES = ['file', 'process', 'network', 'user', 'device', 'log', 'audit']
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical']
const LIMITS = [50, 100, 250]

export default function Events() {
  const [params, setParams] = useSearchParams()
  const [events, setEvents] = useState<UniversalEvent[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)

  const hostname = params.get('hostname') ?? ''
  const category  = params.get('category') ?? ''
  const severity  = params.get('severity') ?? ''
  const limit     = Number(params.get('limit') ?? '50')
  const offset    = Number(params.get('offset') ?? '0')

  const setParam = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value); else next.delete(key)
    next.delete('offset')
    setParams(next)
  }

  const setOffset = (n: number) => {
    const next = new URLSearchParams(params)
    if (n > 0) next.set('offset', String(n)); else next.delete('offset')
    setParams(next)
  }

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const q: EventQueryParams = { limit, offset }
      if (hostname) q.hostname = hostname
      if (category) q.category = category
      if (severity) q.severity = severity
      const data = await eventsApi.list(q)
      setEvents(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [hostname, category, severity, limit, offset])

  useEffect(() => { void load() }, [load])

  const page = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit) || 1

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Événements</h1>

      <div className="flex flex-wrap gap-2">
        <Input
          type="text"
          placeholder="Hostname"
          value={hostname}
          onChange={(e) => setParam('hostname', e.target.value)}
          className="flex-1 min-w-[140px]"
        />
        <Select value={category} onChange={(e) => setParam('category', e.target.value)}>
          <option value="">Catégorie</option>
          {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </Select>
        <Select value={severity} onChange={(e) => setParam('severity', e.target.value)}>
          <option value="">Sévérité</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
        <Select value={limit} onChange={(e) => setParam('limit', e.target.value)}>
          {LIMITS.map((l) => <option key={l} value={l}>{l} / page</option>)}
        </Select>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Temps</th>
              <th className="text-left px-3 py-2.5">Sév.</th>
              <th className="text-left px-3 py-2.5">Cat.</th>
              <th className="text-left px-3 py-2.5">Type</th>
              <th className="text-left px-3 py-2.5">Hostname</th>
              <th className="text-left px-3 py-2.5">Processus</th>
              <th className="text-left px-3 py-2.5">Ressource</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={7} />}
            {!loading && events.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={List}
                    title="Aucun événement"
                    description="Les événements apparaîtront ici dès que l'agent envoie des données"
                  />
                </td>
              </tr>
            )}
            {events.map((ev) => (
              <React.Fragment key={ev.event_id}>
                <tr
                  onClick={() => setExpanded(expanded === ev.event_id ? null : ev.event_id)}
                  className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40 cursor-pointer"
                >
                  <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400">
                    <RelativeTime iso={new Date(ev.timestamp_ns / 1_000_000).toISOString()} />
                  </td>
                  <td className="px-3 py-2.5"><SeverityBadge severity={ev.severity} /></td>
                  <td className="px-3 py-2.5 text-gray-600 dark:text-gray-300">{ev.category}</td>
                  <td className="px-3 py-2.5 text-gray-600 dark:text-gray-300 font-mono text-xs">{ev.type}</td>
                  <td className="px-3 py-2.5 text-gray-700 dark:text-gray-200">{ev.hostname}</td>
                  <td className="px-3 py-2.5 text-gray-600 dark:text-gray-300 font-mono text-xs">{ev.process_name}</td>
                  <td className="px-3 py-2.5 text-gray-400 dark:text-gray-500 font-mono text-xs truncate max-w-[200px]">{ev.resource}</td>
                </tr>
                {expanded === ev.event_id && (
                  <tr>
                    <td colSpan={7} className="px-3 py-3 bg-gray-50 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
                      <pre className="text-xs text-gray-700 dark:text-gray-300 overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(ev, null, 2)}
                      </pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-500">
        <span>{total} événement{total !== 1 ? 's' : ''}</span>
        <div className="flex items-center gap-3">
          <span className="text-xs">{page} / {totalPages}</span>
          <div className="flex gap-1">
            <button
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
              className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            >
              ← Préc.
            </button>
            <button
              disabled={offset + limit >= total}
              onClick={() => setOffset(offset + limit)}
              className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            >
              Suiv. →
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
