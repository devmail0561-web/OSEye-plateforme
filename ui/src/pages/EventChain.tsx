import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, GitBranch } from 'lucide-react'
import { chainApi, type UniversalEvent } from '@/api/client'
import { Spinner } from '@/components/ui'
import RelativeTime from '@/components/RelativeTime'

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400',
  high:     'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-400',
  medium:   'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-400',
  low:      'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-400',
  info:     'bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400',
}

export default function EventChain() {
  const { id } = useParams<{ id: string }>()
  const [chain, setChain] = useState<UniversalEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    chainApi.get(id)
      .then(setChain)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false))
  }, [id])

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link
          to="/events"
          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <GitBranch className="w-5 h-5 text-indigo-500" />
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
          Chaîne d'incident
        </h1>
        {chain.length > 0 && (
          <span className="text-xs text-gray-400 dark:text-gray-500">
            {chain.length} événement{chain.length > 1 ? 's' : ''}
          </span>
        )}
      </div>

      {loading && (
        <div className="flex justify-center py-12">
          <div className="animate-spin w-6 h-6 border-2 border-indigo-500 border-t-transparent rounded-full" />
        </div>
      )}

      {error && (
        <div className="text-red-500 text-sm text-center py-8">{error}</div>
      )}

      {!loading && !error && chain.length > 0 && (
        <div className="relative pl-6">
          {/* Vertical timeline line */}
          <div className="absolute left-2 top-0 bottom-0 w-0.5 bg-gray-200 dark:bg-gray-700" />

          <div className="space-y-3">
            {chain.map((ev, i) => (
              <div key={ev.event_id} className="relative">
                {/* Timeline dot */}
                <div className={`absolute -left-6 top-3 w-3 h-3 rounded-full border-2 border-white dark:border-gray-950
                  ${i === 0 ? 'bg-indigo-500' : 'bg-gray-300 dark:bg-gray-600'}`} />

                <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3 space-y-2">
                  <div className="flex items-start justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${SEV_COLOR[ev.severity] ?? SEV_COLOR.info}`}>
                        {ev.severity}
                      </span>
                      <span className="text-xs text-gray-500 dark:text-gray-400 font-medium uppercase tracking-wide">
                        {ev.category}
                      </span>
                      {ev.type && (
                        <span className="text-xs text-gray-400 dark:text-gray-500">· {ev.type}</span>
                      )}
                    </div>
                    <div className="text-xs text-gray-400 dark:text-gray-500 flex-shrink-0">
                      <RelativeTime ts={new Date(ev.timestamp_ns / 1_000_000).toISOString()} />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-1 text-xs">
                    {ev.hostname && (
                      <div>
                        <span className="text-gray-400 dark:text-gray-500">Host</span>
                        <div className="font-medium text-gray-700 dark:text-gray-300 truncate">{ev.hostname}</div>
                      </div>
                    )}
                    {ev.process_name && (
                      <div>
                        <span className="text-gray-400 dark:text-gray-500">Process</span>
                        <div className="font-mono text-gray-700 dark:text-gray-300 truncate">{ev.process_name}</div>
                      </div>
                    )}
                    {ev.pid !== undefined && ev.pid !== 0 && (
                      <div>
                        <span className="text-gray-400 dark:text-gray-500">PID</span>
                        <div className="font-mono text-gray-700 dark:text-gray-300">{ev.pid}</div>
                      </div>
                    )}
                    {ev.resource && (
                      <div className="col-span-2">
                        <span className="text-gray-400 dark:text-gray-500">Resource</span>
                        <div className="font-mono text-gray-700 dark:text-gray-300 truncate">{ev.resource}</div>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs text-gray-400 dark:text-gray-600">{ev.event_id}</span>
                    {ev.collector && (
                      <span className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 px-1.5 rounded">
                        {ev.collector}
                      </span>
                    )}
                    {ev.os && (
                      <span className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 px-1.5 rounded">
                        {ev.os}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {!loading && !error && chain.length === 0 && (
        <div className="text-center py-12 text-gray-400 dark:text-gray-500 text-sm">
          Cet événement n'appartient à aucune chaîne d'incident.
        </div>
      )}
    </div>
  )
}
