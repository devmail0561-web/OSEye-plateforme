import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { alertsApi, type AlertQueryParams } from '@/api/client'
import { useAlertStore } from '@/stores/alertStore'
import AlertRow from '@/components/AlertRow'
import type { AlertStatus, AlertSeverity } from '@/types'

const STATUSES: AlertStatus[] = ['open', 'acknowledged', 'investigating', 'resolved', 'false_positive']
const SEVERITIES: AlertSeverity[] = ['low', 'medium', 'high', 'critical']
const STATUS_LABELS: Record<AlertStatus, string> = {
  open: 'Ouvert',
  acknowledged: 'Acquitté',
  investigating: 'Investigation',
  resolved: 'Résolu',
  false_positive: 'Faux positif',
}
const LIMITS = [25, 50, 100]

export default function Alerts() {
  const [params, setParams] = useSearchParams()
  const [alerts, setAlerts] = useState(useAlertStore.getState().alerts)
  const [total, setTotal] = useState(0)
  const [isLoading, setIsLoading] = useState(false)
  const updateAlert = useAlertStore((s) => s.updateAlert)

  const status = (params.get('status') ?? '') as AlertStatus | ''
  const severity = (params.get('severity') ?? '') as AlertSeverity | ''
  const hostname = params.get('hostname') ?? ''
  const limit = Number(params.get('limit') ?? '50')
  const offset = Number(params.get('offset') ?? '0')

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
    setIsLoading(true)
    try {
      const q: AlertQueryParams = { limit, offset }
      if (status) q.status = status
      if (severity) q.severity = severity
      if (hostname) q.hostname = hostname
      const data = await alertsApi.list(q)
      setAlerts(data.items)
      setTotal(data.total)
    } finally {
      setIsLoading(false)
    }
  }, [status, severity, hostname, limit, offset])

  useEffect(() => { void load() }, [load])

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Alertes</h1>

      <div className="flex flex-wrap gap-2 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3">
        <select
          value={status}
          onChange={(e) => setParam('status', e.target.value)}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white"
        >
          <option value="">Statut</option>
          {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABELS[s]}</option>)}
        </select>
        <select
          value={severity}
          onChange={(e) => setParam('severity', e.target.value)}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white"
        >
          <option value="">Sévérité</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input
          type="text"
          placeholder="Hostname"
          value={hostname}
          onChange={(e) => setParam('hostname', e.target.value)}
          className="flex-1 min-w-[120px] bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
        />
        <select
          value={limit}
          onChange={(e) => setParam('limit', e.target.value)}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white"
        >
          {LIMITS.map((l) => <option key={l} value={l}>{l} / page</option>)}
        </select>
      </div>

      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-400 text-xs uppercase">
              <th className="text-left px-3 py-2">Temps</th>
              <th className="text-left px-3 py-2">Sév.</th>
              <th className="text-left px-3 py-2">Titre</th>
              <th className="text-left px-3 py-2">Hostname</th>
              <th className="text-left px-3 py-2">Statut</th>
              <th className="text-left px-3 py-2">Assigné</th>
              <th className="text-left px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={7} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Chargement…</td></tr>
            )}
            {!isLoading && alerts.length === 0 && (
              <tr><td colSpan={7} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Aucune alerte</td></tr>
            )}
            {alerts.map((a) => (
              <AlertRow
                key={a.alert_id}
                alert={a}
                onUpdate={(updated) => {
                  updateAlert(updated)
                  setAlerts((prev) => prev.map((x) => x.alert_id === updated.alert_id ? updated : x))
                }}
              />
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-400">
        <span>{total} alertes au total</span>
        <div className="flex gap-2">
          <button
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - limit))}
            className="px-3 py-1 bg-gray-100 dark:bg-gray-800 rounded disabled:opacity-40 hover:bg-gray-300 dark:hover:bg-gray-700"
          >
            ← Préc.
          </button>
          <button
            disabled={offset + limit >= total}
            onClick={() => setOffset(offset + limit)}
            className="px-3 py-1 bg-gray-100 dark:bg-gray-800 rounded disabled:opacity-40 hover:bg-gray-300 dark:hover:bg-gray-700"
          >
            Suiv. →
          </button>
        </div>
      </div>
    </div>
  )
}
