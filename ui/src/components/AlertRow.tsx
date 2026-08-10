import { useState } from 'react'
import type { Alert } from '@/types'
import { alertsApi } from '@/api/client'
import { useAlertStore } from '@/stores/alertStore'
import SeverityBadge from './SeverityBadge'
import RelativeTime from './RelativeTime'

const STATUS_LABELS: Record<string, string> = {
  open: 'Ouvert',
  acknowledged: 'Acquitté',
  investigating: 'Investigation',
  resolved: 'Résolu',
  false_positive: 'FP',
}

export default function AlertRow({ alert, onUpdate }: { alert: Alert; onUpdate?: (a: Alert) => void }) {
  const storeUpdate = useAlertStore((s) => s.updateAlert)
  const [expanded, setExpanded] = useState(false)
  const [loading, setLoading] = useState(false)

  async function doAction(fn: () => Promise<Alert>) {
    setLoading(true)
    try {
      const updated = await fn()
      storeUpdate(updated)
      onUpdate?.(updated)
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <tr
        className="border-b border-gray-200 dark:border-gray-800/50 hover:bg-gray-100/40 dark:bg-gray-800/20 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-3 py-2"><RelativeTime iso={alert.created_at} /></td>
        <td className="px-3 py-2"><SeverityBadge severity={alert.severity} /></td>
        <td className="px-3 py-2 text-gray-900 dark:text-white font-medium max-w-[280px] truncate">{alert.title}</td>
        <td className="px-3 py-2 text-gray-400 dark:text-gray-400">{alert.hostname}</td>
        <td className="px-3 py-2">
          <span className="text-xs text-gray-400 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 rounded px-1.5 py-0.5">
            {STATUS_LABELS[alert.status] ?? alert.status}
          </span>
        </td>
        <td className="px-3 py-2 text-gray-400 dark:text-gray-400 text-xs">{alert.assigned_to ?? '—'}</td>
        <td className="px-3 py-2">
          <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
            {alert.status === 'open' && (
              <>
                <button
                  disabled={loading}
                  onClick={() => doAction(() => alertsApi.acknowledge(alert.alert_id))}
                  className="text-xs px-2 py-0.5 bg-blue-100 hover:bg-blue-200 text-blue-800 dark:bg-blue-900 dark:hover:bg-blue-800 dark:text-blue-200 rounded disabled:opacity-40"
                >
                  Acquitter
                </button>
                <button
                  disabled={loading}
                  onClick={() => doAction(() => alertsApi.falsePositive(alert.alert_id))}
                  className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-300 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded disabled:opacity-40"
                >
                  FP
                </button>
              </>
            )}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="px-3 py-3 bg-white dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
            <div className="space-y-2 text-xs text-gray-700 dark:text-gray-300">
              <p><span className="text-gray-400 dark:text-gray-500">Entity:</span> {alert.entity_id}</p>
              <p><span className="text-gray-400 dark:text-gray-500">Trigger event:</span> {alert.trigger_event_id}</p>
              {alert.mitre_techniques.length > 0 && (
                <p><span className="text-gray-400 dark:text-gray-500">MITRE:</span> {alert.mitre_techniques.join(', ')}</p>
              )}
              {alert.description && <p className="text-gray-400 dark:text-gray-400">{alert.description}</p>}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
