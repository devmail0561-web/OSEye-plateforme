import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { incidentsApi, type IncidentQueryParams } from '@/api/client'
import type { Incident, IncidentStatus, AlertSeverity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'

const STATUSES: IncidentStatus[] = ['open', 'investigating', 'resolved']
const STATUS_STYLES: Record<IncidentStatus, string> = {
  open: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  investigating: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  resolved: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
}

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [hostnameFilter, setHostnameFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState<IncidentStatus | ''>('')
  const [offset, setOffset] = useState(0)
  const limit = 25

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const q: IncidentQueryParams = { page_size: limit, page: Math.floor(offset / limit) + 1 }
      if (hostnameFilter) q.hostname = hostnameFilter
      if (statusFilter) q.status = statusFilter
      const data = await incidentsApi.list(q)
      setIncidents(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [hostnameFilter, statusFilter, offset])

  useEffect(() => { void load() }, [load])

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Incidents</h1>

      <div className="flex flex-wrap gap-2 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3">
        <input
          type="text"
          placeholder="Hostname"
          value={hostnameFilter}
          onChange={(e) => { setHostnameFilter(e.target.value); setOffset(0) }}
          className="flex-1 min-w-[120px] bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
        />
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value as IncidentStatus | ''); setOffset(0) }}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white"
        >
          <option value="">Statut</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-400 text-xs uppercase">
              <th className="text-left px-3 py-2">Hostname</th>
              <th className="text-left px-3 py-2">Sév.</th>
              <th className="text-left px-3 py-2">Statut</th>
              <th className="text-left px-3 py-2">Alertes</th>
              <th className="text-left px-3 py-2">MITRE</th>
              <th className="text-left px-3 py-2">Règle corrélation</th>
              <th className="text-left px-3 py-2">Créé</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={7} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Chargement…</td></tr>
            )}
            {!loading && incidents.length === 0 && (
              <tr><td colSpan={7} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Aucun incident</td></tr>
            )}
            {incidents.map((inc) => (
              <tr key={inc.incident_id} className="border-b border-gray-200 dark:border-gray-800/50 hover:bg-gray-100/40 dark:bg-gray-800/20">
                <td className="px-3 py-2">
                  <Link
                    to={`/incidents/${inc.incident_id}`}
                    className="text-blue-400 hover:text-blue-300 font-medium"
                  >
                    {inc.hostname}
                  </Link>
                </td>
                <td className="px-3 py-2"><SeverityBadge severity={inc.severity as AlertSeverity} /></td>
                <td className="px-3 py-2">
                  <span className={`text-xs px-1.5 py-0.5 rounded ${STATUS_STYLES[inc.status]}`}>
                    {inc.status}
                  </span>
                </td>
                <td className="px-3 py-2 text-gray-400 dark:text-gray-400 tabular-nums">{inc.alert_count}</td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-0.5">
                    {inc.mitre_tactics.slice(0, 3).map((t) => (
                      <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400 px-1 rounded font-mono">{t}</span>
                    ))}
                    {inc.mitre_tactics.length > 3 && (
                      <span className="text-xs text-gray-400 dark:text-gray-500">+{inc.mitre_tactics.length - 3}</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2 text-gray-400 dark:text-gray-400 font-mono text-xs">{inc.correlation_rule}</td>
                <td className="px-3 py-2"><RelativeTime iso={inc.created_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-400">
        <span>{total} incidents au total</span>
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
