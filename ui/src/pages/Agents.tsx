import { useState, useEffect, useCallback } from 'react'
import { Monitor } from 'lucide-react'
import { agentsApi, type AgentInfo } from '@/api/client'
import { Badge, EmptyState, Spinner } from '@/components/ui'
import RelativeTime from '@/components/RelativeTime'

export default function Agents() {
  const [agents, setAgents] = useState<AgentInfo[]>([])
  const [loading, setLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await agentsApi.list()
      setAgents(data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  const online = agents.filter((a) => a.online).length

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Agents</h1>
        <span className="text-xs text-gray-400 dark:text-gray-500">
          {online} en ligne · {agents.length} total
        </span>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Statut</th>
              <th className="text-left px-3 py-2.5">Hostname (CN)</th>
              <th className="text-left px-3 py-2.5">IP</th>
              <th className="text-left px-3 py-2.5">Profil actif</th>
              <th className="text-left px-3 py-2.5">Version</th>
              <th className="text-left px-3 py-2.5">Première vue</th>
              <th className="text-left px-3 py-2.5">Dernière activité</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={7} />}
            {!loading && agents.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={Monitor}
                    title="Aucun agent"
                    description="Les agents apparaissent ici dès leur première connexion gRPC"
                  />
                </td>
              </tr>
            )}
            {agents.map((a) => (
              <tr key={a.cn} className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40">
                <td className="px-3 py-2.5">
                  <span className="flex items-center gap-1.5">
                    <span className={`w-2 h-2 rounded-full inline-block ${a.online ? 'bg-green-400' : 'bg-gray-400 dark:bg-gray-600'}`} />
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {a.online ? 'En ligne' : 'Hors ligne'}
                    </span>
                  </span>
                </td>
                <td className="px-3 py-2.5 font-mono text-xs font-medium text-gray-800 dark:text-gray-200">{a.cn}</td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 font-mono text-xs">{a.ip_address ?? '—'}</td>
                <td className="px-3 py-2.5">
                  <Badge variant="default">{a.active_profile}</Badge>
                </td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 font-mono text-xs">{a.version ?? '—'}</td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 text-xs">
                  {a.first_seen ? <RelativeTime iso={a.first_seen} /> : '—'}
                </td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 text-xs">
                  {a.last_seen ? <RelativeTime iso={a.last_seen} /> : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
