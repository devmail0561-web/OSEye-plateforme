import { useState } from 'react'
import type { Alert } from '@/types'
import { alertsApi } from '@/api/client'
import { useAlertStore } from '@/stores/alertStore'
import SeverityBadge from './SeverityBadge'
import RelativeTime from './RelativeTime'
import { Badge, Button } from './ui'

const STATUS_LABELS: Record<string, string> = {
  open:          'Ouvert',
  acknowledged:  'Acquitté',
  investigating: 'Investigation',
  resolved:      'Résolu',
  false_positive:'FP',
}

const STATUS_VARIANT: Record<string, 'default' | 'blue' | 'amber' | 'green'> = {
  open:          'blue',
  acknowledged:  'amber',
  investigating: 'amber',
  resolved:      'green',
  false_positive:'default',
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
        className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40 cursor-pointer"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400"><RelativeTime iso={alert.created_at} /></td>
        <td className="px-3 py-2.5"><SeverityBadge severity={alert.severity} /></td>
        <td className="px-3 py-2.5 text-gray-800 dark:text-gray-200 font-medium max-w-[280px] truncate">{alert.title}</td>
        <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400">{alert.hostname}</td>
        <td className="px-3 py-2.5">
          <Badge variant={STATUS_VARIANT[alert.status] ?? 'default'}>
            {STATUS_LABELS[alert.status] ?? alert.status}
          </Badge>
        </td>
        <td className="px-3 py-2.5 text-gray-400 dark:text-gray-500 text-xs">{alert.assigned_to ?? '—'}</td>
        <td className="px-3 py-2.5">
          <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
            {alert.status === 'open' && (
              <>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={loading}
                  onClick={() => doAction(() => alertsApi.acknowledge(alert.alert_id))}
                  className="bg-blue-50 hover:bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:hover:bg-blue-900/60 dark:text-blue-300"
                >
                  Acquitter
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={loading}
                  onClick={() => doAction(() => alertsApi.falsePositive(alert.alert_id))}
                >
                  FP
                </Button>
              </>
            )}
          </div>
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="px-4 py-3 bg-gray-50 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800">
            <div className="space-y-1.5 text-xs text-gray-600 dark:text-gray-300">
              <p><span className="text-gray-400 dark:text-gray-500 font-medium">Entity :</span> {alert.entity_id}</p>
              <p><span className="text-gray-400 dark:text-gray-500 font-medium">Trigger event :</span> {alert.trigger_event_id}</p>
              {alert.mitre_techniques.length > 0 && (
                <p><span className="text-gray-400 dark:text-gray-500 font-medium">MITRE :</span> {alert.mitre_techniques.join(', ')}</p>
              )}
              {alert.description && <p className="text-gray-500 dark:text-gray-400 leading-relaxed">{alert.description}</p>}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}
