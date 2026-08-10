import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { casesApi, type CaseQueryParams, type CaseCreateBody } from '@/api/client'
import type { ForensicCase, CaseStatus, AlertSeverity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'

const STATUSES: CaseStatus[] = ['open', 'in_progress', 'resolved', 'archived']
const STATUS_LABELS: Record<CaseStatus, string> = {
  open: 'Ouvert',
  in_progress: 'En cours',
  resolved: 'Résolu',
  archived: 'Archivé',
}
const STATUS_STYLES: Record<CaseStatus, string> = {
  open: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  in_progress: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  resolved: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  archived: 'bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400',
}
const SEVERITIES: AlertSeverity[] = ['low', 'medium', 'high', 'critical']

function NewCaseModal({ onClose, onCreate }: {
  onClose: () => void
  onCreate: (c: ForensicCase) => void
}) {
  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<AlertSeverity>('medium')
  const [description, setDescription] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!title.trim()) return
    setLoading(true)
    setError('')
    try {
      const body: CaseCreateBody = { title: title.trim(), severity, description }
      const c = await casesApi.create(body)
      onCreate(c)
    } catch {
      setError('Erreur lors de la création')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-xl p-6 w-full max-w-md space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Nouveau cas</h2>
        <form onSubmit={submit} className="space-y-3">
          <input
            required
            type="text"
            placeholder="Titre *"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
          />
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as AlertSeverity)}
            className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 text-sm text-gray-900 dark:text-white"
          >
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description…"
            rows={3}
            className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 resize-none"
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex justify-end gap-2">
            <button type="button" onClick={onClose} className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded hover:bg-gray-300 dark:hover:bg-gray-700 text-sm">
              Annuler
            </button>
            <button type="submit" disabled={loading} className="px-4 py-2 bg-blue-600 hover:bg-blue-500 dark:bg-blue-700 dark:hover:bg-blue-600 text-gray-900 dark:text-white rounded text-sm disabled:opacity-40">
              Créer
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

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
      if (statusFilter) q.status_filter = statusFilter
      if (severityFilter) q.severity = severityFilter
      const data = await casesApi.list(q)
      setCases(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [statusFilter, severityFilter, offset])

  useEffect(() => { void load() }, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Cas forensiques</h1>
        <button
          onClick={() => setShowNew(true)}
          className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 dark:bg-blue-700 dark:hover:bg-blue-600 text-gray-900 dark:text-white text-sm rounded"
        >
          + Nouveau cas
        </button>
      </div>

      <div className="flex flex-wrap gap-2 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3">
        <select
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value as CaseStatus | ''); setOffset(0) }}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white"
        >
          <option value="">Statut</option>
          {STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABELS[s]}</option>)}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value as AlertSeverity | ''); setOffset(0) }}
          className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white"
        >
          <option value="">Sévérité</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-400 text-xs uppercase">
              <th className="text-left px-3 py-2">Titre</th>
              <th className="text-left px-3 py-2">Sév.</th>
              <th className="text-left px-3 py-2">Statut</th>
              <th className="text-left px-3 py-2">Alertes</th>
              <th className="text-left px-3 py-2">Assigné</th>
              <th className="text-left px-3 py-2">Créé</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Chargement…</td></tr>
            )}
            {!loading && cases.length === 0 && (
              <tr><td colSpan={6} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Aucun cas</td></tr>
            )}
            {cases.map((c) => (
              <tr key={c.case_id} className="border-b border-gray-200 dark:border-gray-800/50 hover:bg-gray-100/40 dark:bg-gray-800/20">
                <td className="px-3 py-2">
                  <Link
                    to={`/cases/${c.case_id}`}
                    className="text-blue-400 hover:text-blue-300 font-medium"
                  >
                    {c.title}
                  </Link>
                  {c.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {c.tags.map((t) => (
                        <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400 px-1 rounded">{t}</span>
                      ))}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2"><SeverityBadge severity={c.severity} /></td>
                <td className="px-3 py-2">
                  <span className={`text-xs px-1.5 py-0.5 rounded ${STATUS_STYLES[c.status]}`}>
                    {STATUS_LABELS[c.status]}
                  </span>
                </td>
                <td className="px-3 py-2 text-gray-400 dark:text-gray-400">{c.alert_ids.length}</td>
                <td className="px-3 py-2 text-gray-400 dark:text-gray-400">{c.assigned_to ?? '—'}</td>
                <td className="px-3 py-2"><RelativeTime iso={c.created_at} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-400">
        <span>{total} cas au total</span>
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

      {showNew && (
        <NewCaseModal
          onClose={() => setShowNew(false)}
          onCreate={(c) => { setCases((prev) => [c, ...prev]); setShowNew(false) }}
        />
      )}
    </div>
  )
}
