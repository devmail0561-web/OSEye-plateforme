import { useState } from 'react'
import { decisionsApi } from '@/api/client'
import type { Decision, DecisionType } from '@/types'
import RelativeTime from '@/components/RelativeTime'
import ScoreBar from './ScoreBar'
import CountdownBadge from './CountdownBadge'
import { Button } from '@/components/ui'

const TYPE_COLORS: Partial<Record<DecisionType, string>> = {
  ALERT:         'text-red-400',
  ESCALATE:      'text-orange-400',
  ISOLATE:       'text-red-500',
  INVESTIGATE:   'text-blue-400',
  REQUEST_HUMAN: 'text-yellow-400',
}

export default function PendingCard({ decision, onDone, canApprove = true }: {
  decision: Decision
  onDone: (d: Decision) => void
  canApprove?: boolean
}) {
  const [note, setNote] = useState('')
  const [loading, setLoading] = useState(false)

  async function act(fn: () => Promise<Decision>) {
    setLoading(true)
    try { onDone(await fn()) } finally { setLoading(false) }
  }

  return (
    <div className="bg-gray-50 dark:bg-gray-900 border border-amber-700/50 dark:border-amber-800/50 rounded-xl p-4 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <span className={`text-sm font-semibold ${TYPE_COLORS[decision.decision_type] ?? 'text-gray-900 dark:text-white'}`}>
            {decision.decision_type}
          </span>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5 font-mono truncate max-w-[200px]">
            {decision.entity_id}
          </p>
        </div>
        <div className="text-right shrink-0">
          {decision.timeout_at && <CountdownBadge iso={decision.timeout_at} />}
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
            <RelativeTime iso={decision.created_at} />
          </p>
        </div>
      </div>

      <p className="text-xs text-gray-600 dark:text-gray-300 leading-relaxed">{decision.explanation}</p>

      <div className="space-y-1.5">
        <ScoreBar label="Règle" value={decision.rule_score} />
        <ScoreBar label="ML"    value={decision.ml_score} />
        <ScoreBar label="TI"    value={decision.ti_score} />
        <ScoreBar label="Final" value={decision.final_score} />
      </div>

      <textarea
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="Note (optionnelle)…"
        rows={2}
        className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2.5 py-1.5 text-xs text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
      />

      {canApprove && (
        <div className="flex gap-2">
          <Button
            variant="ghost"
            size="sm"
            disabled={loading}
            onClick={() => act(() => decisionsApi.approve(decision.decision_id, note))}
            className="flex-1 justify-center bg-green-100 hover:bg-green-200 text-green-800 dark:bg-green-900/50 dark:hover:bg-green-900 dark:text-green-200"
          >
            Approuver
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={loading}
            onClick={() => act(() => decisionsApi.reject(decision.decision_id, note))}
            className="flex-1 justify-center"
          >
            Rejeter
          </Button>
        </div>
      )}
    </div>
  )
}
