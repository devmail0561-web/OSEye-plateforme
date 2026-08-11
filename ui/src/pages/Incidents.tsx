import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle } from 'lucide-react'
import { incidentsApi, type IncidentQueryParams } from '@/api/client'
import type { Incident, IncidentStatus, AlertSeverity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'
import { EmptyState, Spinner, Badge, Input, Select } from '@/components/ui'

const STATUSES: IncidentStatus[] = ['open', 'investigating', 'resolved']
const STATUS_VARIANT: Record<IncidentStatus, 'red' | 'amber' | 'green'> = {
  open:          'red',
  investigating: 'amber',
  resolved:      'green',
}
const STATUS_LABELS: Record<IncidentStatus, string> = {
  open:          'Ouvert',
  investigating: 'Investigation',
  resolved:      'Résolu',
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
      if (statusFilter)   q.status   = statusFilter
      const data = await incidentsApi.list(q)
      setIncidents(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [hostnameFilter, statusFilter, offset])

  useEffect(() => { void load() }, [load])

  const page = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit) || 1

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Incidents</h1>

      <div className="flex flex-wrap gap-2">
        <Input
          type="text"
          placeholder="Hostname"
          value={hostnameFilter}
          onChange={(e) => { setHostnameFilter(e.target.value); setOffset(0) }}
          className="flex-1 min-w-[140px]"
        />
        <Select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value as IncidentStatus | ''); setOffset(0) }}>
          <option value="">Statut</option>
          {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABELS[s]}</option>)}
        </Select>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Hostname</th>
              <th className="text-left px-3 py-2.5">Sév.</th>
              <th className="text-left px-3 py-2.5">Statut</th>
              <th className="text-left px-3 py-2.5">Alertes</th>
              <th className="text-left px-3 py-2.5">MITRE</th>
              <th className="text-left px-3 py-2.5">Corrélation</th>
              <th className="text-left px-3 py-2.5">Créé</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={7} />}
            {!loading && incidents.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={AlertTriangle}
                    title="Aucun incident"
                    description="Les incidents sont créés automatiquement par corrélation d'alertes sur un même hôte"
                  />
                </td>
              </tr>
            )}
            {incidents.map((inc) => (
              <tr key={inc.incident_id} className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40">
                <td className="px-3 py-2.5">
                  <Link to={`/incidents/${inc.incident_id}`} className="text-blue-500 hover:text-blue-400 font-medium">
                    {inc.hostname}
                  </Link>
                </td>
                <td className="px-3 py-2.5"><SeverityBadge severity={inc.severity as AlertSeverity} /></td>
                <td className="px-3 py-2.5">
                  <Badge variant={STATUS_VARIANT[inc.status]}>{STATUS_LABELS[inc.status]}</Badge>
                </td>
                <td className="px-3 py-2.5 text-gray-600 dark:text-gray-300 tabular-nums">{inc.alert_count}</td>
                <td className="px-3 py-2.5">
                  <div className="flex flex-wrap gap-0.5">
                    {inc.mitre_tactics.slice(0, 3).map((t) => (
                      <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 px-1 rounded font-mono">{t}</span>
                    ))}
                    {inc.mitre_tactics.length > 3 && (
                      <span className="text-xs text-gray-400 dark:text-gray-500">+{inc.mitre_tactics.length - 3}</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 font-mono text-xs">{inc.correlation_rule}</td>
                <td className="px-3 py-2.5"><RelativeTime iso={inc.created_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-500">
        <span>{total} incidents au total</span>
        <div className="flex items-center gap-3">
          <span className="text-xs">{page} / {totalPages}</span>
          <div className="flex gap-1">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">← Préc.</button>
            <button disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)} className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">Suiv. →</button>
          </div>
        </div>
      </div>
    </div>
  )
}
