import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { ShieldAlert } from 'lucide-react'
import { entitiesApi, type EntityProfile } from '@/api/client'
import { EmptyState, Spinner } from '@/components/ui'
import RelativeTime from '@/components/RelativeTime'

const RISK_COLOR = (score: number) => {
  if (score >= 70) return 'text-red-600 dark:text-red-400'
  if (score >= 40) return 'text-orange-500 dark:text-orange-400'
  if (score >= 15) return 'text-yellow-500 dark:text-yellow-400'
  return 'text-green-600 dark:text-green-400'
}

const TYPE_LABEL: Record<string, string> = {
  process:    'Processus',
  user:       'Utilisateur',
  connection: 'Connexion',
  file:       'Fichier',
}

export default function Entities() {
  const [params, setParams] = useSearchParams()
  const [entities, setEntities] = useState<EntityProfile[]>([])
  const [loading, setLoading] = useState(false)

  const hostname = params.get('hostname') ?? ''

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await entitiesApi.list(hostname || undefined)
      setEntities(data)
    } finally {
      setLoading(false)
    }
  }, [hostname])

  useEffect(() => { void load() }, [load])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Entités</h1>
        <div className="flex gap-2 items-center">
          <input
            type="text"
            placeholder="Filtrer par hostname…"
            value={hostname}
            onChange={(e) => {
              const next = new URLSearchParams(params)
              if (e.target.value) next.set('hostname', e.target.value)
              else next.delete('hostname')
              setParams(next)
            }}
            className="text-sm border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-1.5
                       bg-white dark:bg-gray-900 text-gray-900 dark:text-white
                       focus:outline-none focus:ring-2 focus:ring-indigo-500 w-52"
          />
        </div>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Entité</th>
              <th className="text-left px-3 py-2.5">Type</th>
              <th className="text-left px-3 py-2.5">Hostname</th>
              <th className="text-right px-3 py-2.5">Risk score</th>
              <th className="text-right px-3 py-2.5">Alertes</th>
              <th className="text-left px-3 py-2.5">Dernière activité</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={6} />}
            {!loading && entities.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState
                    icon={ShieldAlert}
                    title="Aucune entité"
                    description="Les entités apparaissent dès que des alertes sont générées"
                  />
                </td>
              </tr>
            )}
            {entities.map((e) => (
              <tr
                key={e.entity_id}
                className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
              >
                <td className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300 max-w-xs truncate">
                  {e.entity_id}
                </td>
                <td className="px-3 py-2 text-gray-500 dark:text-gray-400 text-xs">
                  {TYPE_LABEL[e.entity_type] ?? e.entity_type}
                </td>
                <td className="px-3 py-2 text-gray-600 dark:text-gray-400 text-xs">
                  {e.hostname}
                </td>
                <td className="px-3 py-2 text-right">
                  <span className={`font-semibold tabular-nums ${RISK_COLOR(e.risk_score)}`}>
                    {e.risk_score.toFixed(1)}
                  </span>
                </td>
                <td className="px-3 py-2 text-right text-gray-600 dark:text-gray-400">
                  {e.alert_count}
                </td>
                <td className="px-3 py-2 text-gray-500 dark:text-gray-400 text-xs">
                  {e.last_seen ? <RelativeTime ts={e.last_seen} /> : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
