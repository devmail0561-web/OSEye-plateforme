import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { FolderOpen } from 'lucide-react'
import { casesApi, type CaseQueryParams } from '@/api/client'
import type { ForensicCase, CaseStatus, AlertSeverity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'
import NewCaseModal from '@/components/cases/NewCaseModal'
import { EmptyState, Spinner, Badge, Button, Select } from '@/components/ui'

const STATUSES: CaseStatus[] = ['open', 'in_progress', 'resolved', 'archived']
const STATUS_LABELS: Record<CaseStatus, string> = {
  open:       'Ouvert',
  in_progress:'En cours',
  resolved:   'Résolu',
  archived:   'Archivé',
}
const STATUS_VARIANT: Record<CaseStatus, 'blue' | 'amber' | 'green' | 'default'> = {
  open:       'blue',
  in_progress:'amber',
  resolved:   'green',
  archived:   'default',
}
const SEVERITIES: AlertSeverity[] = ['low', 'medium', 'high', 'critical']

export default function Cases() {
  const [cases, setCases] = useState<ForensicCase[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState<CaseStatus | ''>('')
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | ''>('')
  const [offset, setOffset] = useState(0)
  const [showNew, setShowNew] = useState(false)
  const limit = 25

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const q: CaseQueryParams = { page_size: limit, page: Math.floor(offset / limit) + 1 }
      if (statusFilter)   q.status_filter = statusFilter
      if (severityFilter) q.severity = severityFilter
      const data = await casesApi.list(q)
      setCases(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [statusFilter, severityFilter, offset])

  useEffect(() => { void load() }, [load])

  const page = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit) || 1

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Cas forensiques</h1>
        <Button variant="primary" size="sm" onClick={() => setShowNew(true)}>
          + Nouveau cas
        </Button>
      </div>

      <div className="flex flex-wrap gap-2">
        <Select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value as CaseStatus | ''); setOffset(0) }}>
          <option value="">Statut</option>
          {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABELS[s]}</option>)}
        </Select>
        <Select value={severityFilter} onChange={(e) => { setSeverityFilter(e.target.value as AlertSeverity | ''); setOffset(0) }}>
          <option value="">Sévérité</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </Select>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Titre</th>
              <th className="text-left px-3 py-2.5">Sév.</th>
              <th className="text-left px-3 py-2.5">Statut</th>
              <th className="text-left px-3 py-2.5">Alertes</th>
              <th className="text-left px-3 py-2.5">Assigné</th>
              <th className="text-left px-3 py-2.5">Créé</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={6} />}
            {!loading && cases.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={FolderOpen}
                    title="Aucun cas"
                    description="Créez un cas pour regrouper des alertes et conduire une investigation"
                  />
                </td>
              </tr>
            )}
            {cases.map((c) => (
              <tr key={c.case_id} className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40">
                <td className="px-3 py-2.5">
                  <Link to={`/cases/${c.case_id}`} className="text-blue-500 hover:text-blue-400 font-medium">
                    {c.title}
                  </Link>
                  {c.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {c.tags.map((t) => (
                        <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 px-1 rounded">{t}</span>
                      ))}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2.5"><SeverityBadge severity={c.severity} /></td>
                <td className="px-3 py-2.5"><Badge variant={STATUS_VARIANT[c.status]}>{STATUS_LABELS[c.status]}</Badge></td>
                <td className="px-3 py-2.5 text-gray-600 dark:text-gray-300 tabular-nums">{c.alert_ids.length}</td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400">{c.assigned_to ?? '—'}</td>
                <td className="px-3 py-2.5"><RelativeTime iso={c.created_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-500">
        <span>{total} cas</span>
        <div className="flex items-center gap-3">
          <span className="text-xs">{page} / {totalPages}</span>
          <div className="flex gap-1">
            <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">← Préc.</button>
            <button disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)} className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">Suiv. →</button>
          </div>
        </div>
      </div>

      {showNew && (
        <NewCaseModal
          onClose={() => setShowNew(false)}
          onCreate={(c) => { setCases((prev) => [c, ...prev]); setShowNew(false) }}
        />
      )}
    </div>
  )
}
