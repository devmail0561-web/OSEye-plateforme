import RelativeTime from './RelativeTime'

export interface TimelineEntry {
  id: string
  timestamp: string
  label: string
  detail?: string
  severity?: string
}

export default function CaseTimeline({ entries }: { entries: TimelineEntry[] }) {
  if (!entries.length) {
    return <p className="text-gray-400 dark:text-gray-500 text-sm">Aucun événement</p>
  }

  return (
    <ol className="relative border-l border-gray-300 dark:border-gray-700 space-y-4 ml-2">
      {entries.map((e) => (
        <li key={e.id} className="ml-4">
          <div className="absolute w-2.5 h-2.5 bg-blue-500 rounded-full -left-[5px] top-1" />
          <div className="flex items-start gap-2">
            <RelativeTime iso={e.timestamp} />
            <div>
              <p className="text-sm text-gray-900 dark:text-white font-medium">{e.label}</p>
              {e.detail && <p className="text-xs text-gray-400 dark:text-gray-400 mt-0.5">{e.detail}</p>}
            </div>
          </div>
        </li>
      ))}
    </ol>
  )
}
