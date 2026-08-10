import { useState, useEffect, useCallback } from 'react'
import { decisionsApi, type DecisionQueryParams } from '@/api/client'
import type { Decision, DecisionType } from '@/types'
import RelativeTime from '@/components/RelativeTime'
import { useCountdown } from '@/hooks/useCountdown'

const TYPE_COLORS: Partial<Record<DecisionType, string>> = {
  ALERT: 'text-red-300',
  ESCALATE: 'text-orange-300',
  ISOLATE: 'text-red-400',
  INVESTIGATE: 'text-blue-300',
  REQUEST_HUMAN: 'text-yellow-300',
}

const SCORE_COLOR = (s: number) =>
  s >= 0.8 ? 'text-red-400' : s >= 0.5 ? 'text-orange-300' : 'text-green-400'

function ScoreBar({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-gray-400 dark:text-gray-500 w-14 shrink-0">{label}</span>
      <div className="flex-1 bg-gray-100 dark:bg-gray-800 rounded-full h-1.5">
        <div
          className="h-1.5 rounded-full bg-blue-500"
          style={{ width: `${Math.min(value * 100, 100)}%` }}
        />
      </div>
      <span className={`w-10 text-right tabular-nums ${SCORE_COLOR(value)}`}>
        {(value * 100).toFixed(0)}%
      </span>
    </div>
  )
}

function fmtCountdown(s: number): string {
  if (s <= 0) return 'Expiré'
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  return `${Math.floor(s / 3600)}h`
}

function CountdownBadge({ iso }: { iso: string }) {
  const { remaining, expired } = useCountdown(iso)
  return (
    <span className={`text-xs tabular-nums ${expired ? 'text-red-400' : 'text-amber-300'}`}>
      {fmtCountdown(remaining)}
    </span>
  )
}

function PendingCard({ decision, onDone }: { decision: Decision; onDone: (d: Decision) => void }) {
  const [note, setNote] = useState('')
  const [loading, setLoading] = useState(false)

  async function act(fn: () => Promise<Decision>) {
    setLoading(true)
    try {
      const updated = await fn()
      onDone(updated)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-gray-50 dark:bg-gray-900 border border-amber-800/60 rounded-xl p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <span className={`text-sm font-semibold ${TYPE_COLORS[decision.decision_type] ?? 'text-gray-900 dark:text-white'}`}>
            {decision.decision_type}
          </span>
          <p className="text-xs text-gray-400 dark:text-gray-400 mt-0.5 font-mono">{decision.entity_id}</p>
        </div>
        <div className="text-right shrink-0">
          {decision.timeout_at && <CountdownBadge iso={decision.timeout_at} />}
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
            <RelativeTime iso={decision.created_at} />
          </p>
        </div>
      </div>

      <p className="text-xs text-gray-700 dark:text-gray-300 leading-relaxed">{decision.explanation}</p>

      <div className="space-y-1.5">
        <ScoreBar label="Règle" value={decision.rule_score} />
        <ScoreBar label="ML" value={decision.ml_score} />
        <ScoreBar label="TI" value={decision.ti_score} />
        <ScoreBar label="Final" value={decision.final_score} />
      </div>

      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Note (optionnelle)…"
        rows={2}
        className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1.5 text-xs text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 resize-none"
      />

      <div className="flex gap-2">
        <button
          disabled={loading}
          onClick={() => act(() => decisionsApi.approve(decision.decision_id, note))}
          className="flex-1 py-1.5 bg-green-100 hover:bg-green-200 text-green-800 dark:bg-green-900 dark:hover:bg-green-800 dark:text-green-200 text-sm rounded disabled:opacity-40"
        >
          Approuver
        </button>
        <button
          disabled={loading}
          onClick={() => act(() => decisionsApi.reject(decision.decision_id, note))}
          className="flex-1 py-1.5 bg-red-100 hover:bg-red-200 text-red-800 dark:bg-red-900 dark:hover:bg-red-800 dark:text-red-200 text-sm rounded disabled:opacity-40"
        >
          Rejeter
        </button>
      </div>
    </div>
  )
}

function DecisionRow({ d }: { d: Decision }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <>
      <tr
        className="border-b border-gray-200 dark:border-gray-800/50 hover:bg-gray-100/40 dark:bg-gray-800/20 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-3 py-2"><RelativeTime iso={d.created_at} /></td>
        <td className={`px-3 py-2 font-mono text-xs ${TYPE_COLORS[d.decision_type] ?? 'text-gray-900 dark:text-white'}`}>
          {d.decision_type}
        </td>
        <td className="px-3 py-2 text-gray-400 dark:text-gray-400 font-mono text-xs truncate max-w-[180px]">{d.entity_id}</td>
        <td className={`px-3 py-2 tabular-nums text-sm ${SCORE_COLOR(d.final_score)}`}>
          {(d.final_score * 100).toFixed(0)}%
        </td>
        <td className="px-3 py-2">
          {d.requires_human ? (
            <span className={`text-xs px-1.5 py-0.5 rounded ${
              d.human_decision === 'approved' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
              : d.human_decision === 'rejected' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
              : 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200'
            }`}>
              {d.human_decision ?? 'En attente'}
            </span>
          ) : (
            <span className="text-xs text-gray-500 dark:text-gray-600">auto</span>
          )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} className="px-3 py-3 bg-white dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
            <div className="space-y-1.5 text-xs">
              <p className="text-gray-700 dark:text-gray-300 leading-relaxed">{d.explanation}</p>
              {d.human_note && <p><span className="text-gray-400 dark:text-gray-500">Note op.: </span>{d.human_note}</p>}
              <p className="text-gray-400 dark:text-gray-500 font-mono">Policy: {d.policy_version}</p>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

const TYPES: DecisionType[] = [
  'ALERT', 'IGNORE', 'ESCALATE', 'INVESTIGATE', 'ISOLATE', 'REQUEST_HUMAN', 'COLLECT_MORE', 'NOTIFY',
]

export default function Decisions() {
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
      if (humanOnly) q.requires_human = true
      const data = await decisionsApi.list(q)
      setList(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [typeFilter, humanOnly, offset])

  useEffect(() => { void loadPending() }, [loadPending])
  useEffect(() => { void loadList() }, [loadList])

  function handlePendingDone(updated: Decision) {
    setPending((prev) => prev.filter((d) => d.decision_id !== updated.decision_id))
    setList((prev) => prev.map((d) => d.decision_id === updated.decision_id ? updated : d))
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Décisions</h1>

      {pending.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-medium text-amber-300">
            {pending.length} décision{pending.length > 1 ? 's' : ''} en attente d'approbation
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {pending.map((d) => (
              <PendingCard key={d.decision_id} decision={d} onDone={handlePendingDone} />
            ))}
          </div>
        </section>
      )}

      <section className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value as DecisionType | ''); setOffset(0) }}
            className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1 text-sm text-gray-900 dark:text-white"
          >
            <option value="">Type</option>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
            <input
              type="checkbox"
              checked={humanOnly}
              onChange={(e) => { setHumanOnly(e.target.checked); setOffset(0) }}
              className="accent-blue-500"
            />
            Humaine seulement
          </label>
        </div>

        <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-400 text-xs uppercase">
                <th className="text-left px-3 py-2">Temps</th>
                <th className="text-left px-3 py-2">Type</th>
                <th className="text-left px-3 py-2">Entité</th>
                <th className="text-left px-3 py-2">Score</th>
                <th className="text-left px-3 py-2">Validation</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={5} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Chargement…</td></tr>
              )}
              {!loading && list.length === 0 && (
                <tr><td colSpan={5} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Aucune décision</td></tr>
              )}
              {list.map((d) => <DecisionRow key={d.decision_id} d={d} />)}
            </tbody>
          </table>
        </div>

        <div className="flex items-center justify-between text-sm text-gray-400 dark:text-gray-400">
          <span>{total} décisions au total</span>
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
      </section>
    </div>
  )
}
