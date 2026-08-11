import RelativeTime from './RelativeTime'
import SeverityBadge from './SeverityBadge'
import type { AlertSeverity } from '@/types'

export interface TimelineEntry {
  id: string
  timestamp: string
  label: string
  detail?: string
  severity?: string
}

export default function CaseTimeline({ entries }: { entries: TimelineEntry[] }) {
  if (!entries.length) {
    return <p className="text-xs text-gray-400 dark:text-gray-600">Aucune entrée</p>
  }

  return (
    <ol className="relative border-l border-gray-200 dark:border-gray-700 ml-2 space-y-4">
      {entries.map((e) => (
        <li key={e.id} className="ml-5 relative">
          <span className="absolute -left-[1.45rem] top-0.5 w-2.5 h-2.5 rounded-full bg-blue-500 border-2 border-white dark:border-gray-900 ring-2 ring-blue-500/20" />
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-gray-400 dark:text-gray-500 tabular-nums">
              <RelativeTime iso={e.timestamp} />
            </span>
            {e.severity && <SeverityBadge severity={e.severity as AlertSeverity} />}
            <span className="text-sm text-gray-800 dark:text-gray-200 font-medium">{e.label}</span>
          </div>
          {e.detail && (
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">{e.detail}</p>
          )}
        </li>
      ))}
    </ol>
  )
}
