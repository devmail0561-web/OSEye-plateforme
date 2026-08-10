import React, { useState, useEffect, useCallback } from 'react'
import { rulesApi } from '@/api/client'
import type { Rule } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'
import CodeEditor from '@/components/CodeEditor'
import { useTheme } from '@/hooks/useTheme'

const SOURCE_STYLES: Record<string, string> = {
  builtin: 'bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400',
  custom: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  imported: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
}

function RuleDetail({ rule }: { rule: Rule }) {
  const { isDark } = useTheme()
  const [yaml, setYaml] = useState(rule.condition_yaml)
  const [valid, setValid] = useState<boolean | null>(null)
  const [validError, setValidError] = useState<string | null>(null)
  const [validating, setValidating] = useState(false)

  async function validate() {
    setValidating(true)
    setValid(null)
    setValidError(null)
    try {
      const res = await rulesApi.validate(yaml, rule.timeframe ?? undefined)
      setValid(res.valid)
      setValidError(res.error)
    } finally {
      setValidating(false)
    }
  }

  return (
    <div className="px-3 py-3 bg-white dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800 space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-gray-400 dark:text-gray-400">
        <p><span className="text-gray-400 dark:text-gray-500">Matches :</span> {rule.match_count}</p>
        <p><span className="text-gray-400 dark:text-gray-500">Faux pos. :</span> {rule.false_positive_count}</p>
        <p><span className="text-gray-400 dark:text-gray-500">Timeframe :</span> {rule.timeframe ? `${rule.timeframe}s` : '—'}</p>
        <p><span className="text-gray-400 dark:text-gray-500">Dernière match :</span> {rule.last_matched ? <RelativeTime iso={rule.last_matched} /> : '—'}</p>
      </div>
      {rule.mitre.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {rule.mitre.map((m) => (
            <span key={m} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400 px-1.5 py-0.5 rounded font-mono">{m}</span>
          ))}
        </div>
      )}
      {rule.explanation && <p className="text-xs text-gray-400 dark:text-gray-400">{rule.explanation}</p>}
      <div className="space-y-2">
        <p className="text-xs text-gray-400 dark:text-gray-500">Condition YAML</p>
        <div style={{ height: 120 }}>
          <CodeEditor value={yaml} onChange={setYaml} dark={isDark} />
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={validate}
            disabled={validating}
            className="text-xs px-3 py-1 bg-blue-100 hover:bg-blue-200 text-blue-800 dark:bg-blue-900 dark:hover:bg-blue-800 dark:text-blue-200 rounded disabled:opacity-40"
          >
            Valider
          </button>
          {valid === true && <span className="text-xs text-green-400">Syntaxe valide</span>}
          {valid === false && <span className="text-xs text-red-400">{validError ?? 'Invalide'}</span>}
          <span
            title="La modification des règles se fait via CLI (oseye-cli rules edit)"
            className="text-xs text-gray-500 dark:text-gray-600 cursor-help ml-auto"
          >
            Édition via CLI uniquement ⓘ
          </span>
        </div>
      </div>
    </div>
  )
}

export default function Rules() {
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
        <div className="flex items-center gap-2">
          {reloadMsg && <span className="text-xs text-green-400">{reloadMsg}</span>}
          <button
            disabled={reloading}
            onClick={reloadRules}
            className="text-xs px-3 py-1.5 bg-gray-100 dark:bg-gray-800 hover:bg-gray-300 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded disabled:opacity-40"
          >
            Recharger les règles
          </button>
        </div>
      </div>

      <div className="flex items-center gap-3 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3">
        <label className="flex items-center gap-1.5 text-sm text-gray-700 dark:text-gray-300 cursor-pointer">
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

      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-400 text-xs uppercase">
              <th className="text-left px-3 py-2">État</th>
              <th className="text-left px-3 py-2">Nom</th>
              <th className="text-left px-3 py-2">Sév.</th>
              <th className="text-left px-3 py-2">Source</th>
              <th className="text-left px-3 py-2">Tags</th>
              <th className="text-left px-3 py-2">Matches</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Chargement…</td></tr>
            )}
            {!loading && rules.length === 0 && (
              <tr><td colSpan={6} className="px-3 py-6 text-center text-gray-400 dark:text-gray-500">Aucune règle</td></tr>
            )}
            {rules.map((r) => (
              <React.Fragment key={r.id}>
                <tr
                  className="border-b border-gray-200 dark:border-gray-800/50 hover:bg-gray-100/40 dark:bg-gray-800/20 cursor-pointer"
                  onClick={() => setExpanded(expanded === r.id ? null : r.id)}
                >
                  <td className="px-3 py-2">
                    <span
                      title="La désactivation se fait via CLI"
                      className={`inline-block w-2 h-2 rounded-full ${r.enabled ? 'bg-green-400' : 'bg-gray-600'}`}
                    />
                  </td>
                  <td className="px-3 py-2 text-gray-900 dark:text-white font-mono text-xs">{r.name}</td>
                  <td className="px-3 py-2"><SeverityBadge severity={r.severity} /></td>
                  <td className="px-3 py-2">
                    <span className={`text-xs px-1.5 py-0.5 rounded ${SOURCE_STYLES[r.source] ?? 'bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400'}`}>
                      {r.source}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-0.5">
                      {r.tags.slice(0, 3).map((t) => (
                        <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400 px-1 rounded">{t}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-gray-400 dark:text-gray-400 tabular-nums">{r.match_count}</td>
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
