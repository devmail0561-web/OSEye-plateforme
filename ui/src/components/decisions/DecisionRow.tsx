import { useState } from 'react'
import type { Decision, DecisionType } from '@/types'
import RelativeTime from '@/components/RelativeTime'
import ScoreBar from './ScoreBar'
import { Badge } from '@/components/ui'

const TYPE_COLORS: Partial<Record<DecisionType, string>> = {
  ALERT:         'text-red-400',
  ESCALATE:      'text-orange-400',
  ISOLATE:       'text-red-500',
  INVESTIGATE:   'text-blue-400',
  REQUEST_HUMAN: 'text-yellow-400',
}

export default function DecisionRow({ d }: { d: Decision }) {
  const [expanded, setExpanded] = useState(false)
  const scoreColor = d.final_score >= 0.8 ? 'text-red-400' : d.final_score >= 0.5 ? 'text-orange-300' : 'text-green-400'

  return (
    <>
      <tr
        className="border-b border-gray-200 dark:border-gray-800/50 hover:bg-gray-100/40 dark:hover:bg-gray-800/40 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 text-xs"><RelativeTime iso={d.created_at} /></td>
        <td className={`px-3 py-2.5 font-mono text-xs font-medium ${TYPE_COLORS[d.decision_type] ?? 'text-gray-700 dark:text-gray-300'}`}>
          {d.decision_type}
        </td>
        <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 font-mono text-xs truncate max-w-[180px]">
          {d.entity_id}
        </td>
        <td className={`px-3 py-2.5 tabular-nums text-sm font-mono ${scoreColor}`}>
          {(d.final_score * 100).toFixed(0)}%
        </td>
        <td className="px-3 py-2.5">
          {d.requires_human ? (
            <Badge variant={
              d.human_decision === 'approved' ? 'green' :
              d.human_decision === 'rejected' ? 'red' : 'amber'
            }>
              {d.human_decision ?? 'En attente'}
            </Badge>
          ) : (
            <span className="text-xs text-gray-400 dark:text-gray-600">auto</span>
          )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={5} className="px-4 py-3 bg-gray-100/60 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
            <div className="space-y-2">
              <p className="text-xs text-gray-600 dark:text-gray-300 leading-relaxed">{d.explanation}</p>
              <div className="grid grid-cols-2 gap-2 max-w-sm">
                <ScoreBar label="Règle" value={d.rule_score} />
                <ScoreBar label="ML"    value={d.ml_score} />
                <ScoreBar label="TI"    value={d.ti_score} />
                <ScoreBar label="Final" value={d.final_score} />
              </div>
              {d.human_note && (
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  <span className="font-medium">Note op. :</span> {d.human_note}
                </p>
              )}
              <p className="text-xs text-gray-400 dark:text-gray-600 font-mono">Policy: {d.policy_version}</p>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
