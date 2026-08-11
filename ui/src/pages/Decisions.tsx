import { useState, useEffect, useCallback } from 'react'
import { Scale } from 'lucide-react'
import { decisionsApi, type DecisionQueryParams } from '@/api/client'
import type { Decision, DecisionType } from '@/types'
import PendingCard from '@/components/decisions/PendingCard'
import DecisionRow from '@/components/decisions/DecisionRow'
import { EmptyState, Spinner, Select } from '@/components/ui'
import { useAuthStore } from '@/stores/authStore'

const TYPES: DecisionType[] = [
  'ALERT', 'IGNORE', 'ESCALATE', 'INVESTIGATE', 'ISOLATE', 'REQUEST_HUMAN', 'COLLECT_MORE', 'NOTIFY',
]

export default function Decisions() {
  const isAdmin = useAuthStore((s) => s.roles.includes('admin'))
  const [pending, setPending] = useState<Decision[]>([])
  const [list, setList] = useState<Decision[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [typeFilter, setTypeFilter] = useState<DecisionType | ''>('')
  const [humanOnly, setHumanOnly] = useState(false)
  const [offset, setOffset] = useState(0)
  const limit = 50

  const loadPending = useCallback(async () => {
    const data = await decisionsApi.pending()
    setPending(data)
  }, [])

  const loadList = useCallback(async () => {
    setLoading(true)
    try {
      const q: DecisionQueryParams = { page_size: limit, page: Math.floor(offset / limit) + 1 }
      if (typeFilter) q.decision_type = typeFilter
      if (humanOnly)  q.requires_human = true
      const data = await decisionsApi.list(q)
      setList(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [typeFilter, humanOnly, offset])

  useEffect(() => { void loadPending() }, [loadPending])
  useEffect(() => { void loadList()   }, [loadList])

  function handlePendingDone(updated: Decision) {
    setPending((prev) => prev.filter((d) => d.decision_id !== updated.decision_id))
    setList((prev) => prev.map((d) => d.decision_id === updated.decision_id ? updated : d))
  }

  const page = Math.floor(offset / limit) + 1
  const totalPages = Math.ceil(total / limit) || 1

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Décisions</h1>

      {pending.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold text-amber-500 dark:text-amber-400">
            {pending.length} décision{pending.length > 1 ? 's' : ''} en attente d'approbation
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {pending.map((d) => (
              <PendingCard key={d.decision_id} decision={d} onDone={handlePendingDone} canApprove={isAdmin} />
            ))}
          </div>
        </section>
      )}

      <section className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Select value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value as DecisionType | ''); setOffset(0) }}>
            <option value="">Type</option>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </Select>
          <label className="flex items-center gap-1.5 text-sm text-gray-600 dark:text-gray-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={humanOnly}
              onChange={(e) => { setHumanOnly(e.target.checked); setOffset(0) }}
              className="accent-blue-500"
            />
            Humaine seulement
          </label>
        </div>

        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
                <th className="text-left px-3 py-2.5">Temps</th>
                <th className="text-left px-3 py-2.5">Type</th>
                <th className="text-left px-3 py-2.5">Entité</th>
                <th className="text-left px-3 py-2.5">Score</th>
                <th className="text-left px-3 py-2.5">Validation</th>
              </tr>
            </thead>
            <tbody>
              {loading && <Spinner colSpan={5} />}
              {!loading && list.length === 0 && (
                <tr>
                  <td colSpan={5}>
                    <EmptyState
                      icon={Scale}
                      title="Aucune décision"
                      description="Le Decision Engine génère des décisions automatiques à partir des alertes corrélées"
                    />
                  </td>
                </tr>
              )}
              {list.map((d) => <DecisionRow key={d.decision_id} d={d} />)}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-500">
          <span>{total} décision{total !== 1 ? 's' : ''}</span>
          <div className="flex items-center gap-3">
            <span className="text-xs">{page} / {totalPages}</span>
            <div className="flex gap-1">
              <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))} className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">← Préc.</button>
              <button disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)} className="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300 rounded text-xs disabled:opacity-40 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">Suiv. →</button>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
