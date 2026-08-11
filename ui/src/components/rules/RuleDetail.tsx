import { useState } from 'react'
import { CheckCircle, XCircle, Info } from 'lucide-react'
import { rulesApi } from '@/api/client'
import type { Rule } from '@/types'
import RelativeTime from '@/components/RelativeTime'
import CodeEditor from '@/components/CodeEditor'
import { Button } from '@/components/ui'
import { useTheme } from '@/hooks/useTheme'

export default function RuleDetail({ rule }: { rule: Rule }) {
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
    <div className="px-4 py-4 bg-gray-100/60 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800 space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
        {[
          { label: 'Matches',       value: rule.match_count },
          { label: 'Faux positifs', value: rule.false_positive_count },
          { label: 'Timeframe',     value: rule.timeframe ? `${rule.timeframe}s` : '—' },
          { label: 'Dernière match', value: rule.last_matched ? <RelativeTime iso={rule.last_matched} /> : '—' },
        ].map(({ label, value }) => (
          <div key={label}>
            <p className="text-gray-400 dark:text-gray-600 mb-0.5">{label}</p>
            <p className="text-gray-700 dark:text-gray-300 font-medium">{value}</p>
          </div>
        ))}
      </div>

      {rule.mitre.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {rule.mitre.map((m) => (
            <span key={m} className="text-xs bg-gray-200 dark:bg-gray-800 text-gray-600 dark:text-gray-300 px-1.5 py-0.5 rounded font-mono">{m}</span>
          ))}
        </div>
      )}

      {rule.explanation && (
        <p className="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">{rule.explanation}</p>
      )}

      <div className="space-y-2">
        <p className="text-xs font-medium text-gray-500 dark:text-gray-500">Condition YAML</p>
        <div style={{ height: 120 }}>
          <CodeEditor value={yaml} onChange={setYaml} dark={isDark} />
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={validate} disabled={validating}>
            {validating ? 'Validation…' : 'Valider'}
          </Button>
          {valid === true && (
            <span className="flex items-center gap-1 text-xs text-green-500">
              <CheckCircle className="w-3.5 h-3.5" /> Syntaxe valide
            </span>
          )}
          {valid === false && (
            <span className="flex items-center gap-1 text-xs text-red-400">
              <XCircle className="w-3.5 h-3.5" /> {validError ?? 'Invalide'}
            </span>
          )}
          <span
            title="La modification des règles se fait via CLI (oseye-cli rules edit)"
            className="flex items-center gap-1 text-xs text-gray-400 dark:text-gray-600 cursor-help ml-auto"
          >
            <Info className="w-3 h-3" /> Édition via CLI uniquement
          </span>
        </div>
      </div>
    </div>
  )
}
