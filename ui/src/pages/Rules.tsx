import React, { useState, useEffect, useCallback } from 'react'
import { Shield, CheckCircle, XCircle } from 'lucide-react'
import { rulesApi } from '@/api/client'
import type { Rule } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RuleDetail from '@/components/rules/RuleDetail'
import { EmptyState, Spinner, Button } from '@/components/ui'
import { useAuthStore } from '@/stores/authStore'

const SOURCE_VARIANT: Record<string, string> = {
  builtin:  'bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400',
  custom:   'bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-200',
  imported: 'bg-purple-100 text-purple-800 dark:bg-purple-900/60 dark:text-purple-200',
}

export default function Rules() {
  const isAdmin = useAuthStore((s) => s.roles.includes('admin'))
  const [rules, setRules] = useState<Rule[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [enabledOnly, setEnabledOnly] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [reloading, setReloading] = useState(false)
  const [reloadMsg, setReloadMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await rulesApi.list(enabledOnly || undefined)
      setRules(data.items)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }, [enabledOnly])

  useEffect(() => { void load() }, [load])

  async function reloadRules() {
    setReloading(true)
    setReloadMsg('')
    try {
      const res = await rulesApi.reload()
      setReloadMsg(`${res.reloaded} règle(s) rechargée(s)`)
      void load()
    } finally {
      setReloading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Règles de détection</h1>
        {isAdmin && (
          <div className="flex items-center gap-2">
            {reloadMsg && <span className="text-xs text-green-500">{reloadMsg}</span>}
            <Button size="sm" variant="ghost" disabled={reloading} onClick={reloadRules}>
              {reloading ? 'Rechargement…' : 'Recharger les règles'}
            </Button>
          </div>
        )}
      </div>

      <div className="flex items-center gap-3">
        <label className="flex items-center gap-1.5 text-sm text-gray-600 dark:text-gray-300 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={enabledOnly}
            onChange={(e) => setEnabledOnly(e.target.checked)}
            className="accent-blue-500"
          />
          Activées seulement
        </label>
        <span className="text-xs text-gray-400 dark:text-gray-500 ml-auto">{total} règles</span>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5 w-8"></th>
              <th className="text-left px-3 py-2.5">Nom</th>
              <th className="text-left px-3 py-2.5">Sév.</th>
              <th className="text-left px-3 py-2.5">Source</th>
              <th className="text-left px-3 py-2.5">Tags</th>
              <th className="text-left px-3 py-2.5">Matches</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={6} />}
            {!loading && rules.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState icon={Shield} title="Aucune règle" description="Les règles YAML sont chargées depuis le dossier rules/" />
                </td>
              </tr>
            )}
            {rules.map((r) => (
              <React.Fragment key={r.id}>
                <tr
                  className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40 cursor-pointer"
                  onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                >
                  <td className="px-3 py-2.5">
                    {r.enabled
                      ? <CheckCircle className="w-4 h-4 text-green-500" strokeWidth={1.75} />
                      : <XCircle    className="w-4 h-4 text-gray-400 dark:text-gray-600" strokeWidth={1.75} />
                    }
                  </td>
                  <td className="px-3 py-2.5 text-gray-800 dark:text-gray-200 font-mono text-xs">{r.name}</td>
                  <td className="px-3 py-2.5"><SeverityBadge severity={r.severity} /></td>
                  <td className="px-3 py-2.5">
                    <span className={`text-xs px-1.5 py-0.5 rounded ${SOURCE_VARIANT[r.source] ?? SOURCE_VARIANT.builtin}`}>
                      {r.source}
                    </span>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap gap-0.5">
                      {r.tags.slice(0, 3).map((t) => (
                        <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 px-1 rounded">{t}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 tabular-nums">{r.match_count}</td>
                </tr>
                {expanded === r.id && (
                  <tr>
                    <td colSpan={6} className="p-0">
                      <RuleDetail rule={r} />
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
