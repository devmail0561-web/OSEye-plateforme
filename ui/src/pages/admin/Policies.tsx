import { useState, useEffect, useCallback } from 'react'
import { SlidersHorizontal, ChevronDown, ChevronUp } from 'lucide-react'
import { policiesApi } from '@/api/client'
import type { SurveillanceProfile } from '@/types'
import { Badge, Button, EmptyState, Spinner, Input } from '@/components/ui'
import ActionModal from '@/components/admin/ActionModal'

interface ApplyResult {
  profileName: string
  pushedTo: string
}

function ProfileDetail({ profile }: { profile: SurveillanceProfile }) {
  const enabledCollectors = Object.entries(profile.collectors)
    .filter(([, cfg]) => cfg.enabled)
    .map(([name, cfg]) => ({ name, throttle: cfg.throttle }))
  const disabledCollectors = Object.entries(profile.collectors)
    .filter(([, cfg]) => !cfg.enabled)
    .map(([name]) => name)

  return (
    <div className="px-4 py-3 bg-gray-50 dark:bg-gray-950 border-b border-gray-200 dark:border-gray-800 space-y-3 text-xs">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div>
          <p className="text-gray-400 dark:text-gray-600 mb-1">Plateformes</p>
          <div className="flex flex-wrap gap-1">
            {profile.platforms.map((p) => (
              <Badge key={p} variant="default">{p}</Badge>
            ))}
          </div>
        </div>
        <div>
          <p className="text-gray-400 dark:text-gray-600 mb-1">Push interval</p>
          <p className="text-gray-700 dark:text-gray-300 font-medium">{profile.push_interval_s}s</p>
        </div>
        <div>
          <p className="text-gray-400 dark:text-gray-600 mb-1">Sévérité min.</p>
          <Badge variant="default">{profile.min_severity}</Badge>
        </div>
        <div>
          <p className="text-gray-400 dark:text-gray-600 mb-1">Version</p>
          <p className="text-gray-700 dark:text-gray-300 font-medium">{profile.version}</p>
        </div>
      </div>

      {enabledCollectors.length > 0 && (
        <div>
          <p className="text-gray-400 dark:text-gray-600 mb-1">Collecteurs activés</p>
          <div className="flex flex-wrap gap-1.5">
            {enabledCollectors.map(({ name, throttle }) => (
              <span key={name} className="bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300 px-2 py-0.5 rounded font-mono">
                {name} <span className="opacity-60">{throttle}s</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {disabledCollectors.length > 0 && (
        <div>
          <p className="text-gray-400 dark:text-gray-600 mb-1">Collecteurs désactivés</p>
          <div className="flex flex-wrap gap-1.5">
            {disabledCollectors.map((name) => (
              <span key={name} className="bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-600 px-2 py-0.5 rounded font-mono">{name}</span>
            ))}
          </div>
        </div>
      )}

      {profile.ignore_processes.length > 0 && (
        <div>
          <p className="text-gray-400 dark:text-gray-600 mb-1">Processus ignorés</p>
          <p className="text-gray-600 dark:text-gray-400 font-mono">{profile.ignore_processes.join(', ')}</p>
        </div>
      )}
    </div>
  )
}

export default function Policies() {
  const [profiles, setProfiles] = useState<SurveillanceProfile[]>([])
  const [loading, setLoading] = useState(false)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [applyTarget, setApplyTarget] = useState<SurveillanceProfile | null>(null)
  const [agentId, setAgentId] = useState('')
  const [applying, setApplying] = useState(false)
  const [result, setResult] = useState<Record<string, ApplyResult>>({})

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await policiesApi.list()
      setProfiles(data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function handleApply() {
    if (!applyTarget) return
    setApplying(true)
    try {
      const res = await policiesApi.apply(applyTarget.name, agentId.trim() || undefined)
      setResult((prev) => ({
        ...prev,
        [applyTarget.name]: { profileName: res.profile, pushedTo: res.pushed_to },
      }))
      setTimeout(() => {
        setResult((prev) => {
          const next = { ...prev }
          delete next[applyTarget.name]
          return next
        })
      }, 4000)
      setApplyTarget(null)
      setAgentId('')
    } finally {
      setApplying(false)
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Policies de surveillance</h1>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5 w-6"></th>
              <th className="text-left px-3 py-2.5">Profil</th>
              <th className="text-left px-3 py-2.5">Description</th>
              <th className="text-left px-3 py-2.5">Push interval</th>
              <th className="text-left px-3 py-2.5">Action</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={5} />}
            {!loading && profiles.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <EmptyState
                    icon={SlidersHorizontal}
                    title="Aucun profil"
                    description="Les profils de surveillance sont définis dans la configuration serveur"
                  />
                </td>
              </tr>
            )}
            {profiles.map((p) => (
              <>
                <tr
                  key={p.name}
                  className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40 cursor-pointer"
                  onClick={() => setExpanded(expanded === p.name ? null : p.name)}
                >
                  <td className="px-3 py-2.5 text-gray-400 dark:text-gray-600">
                    {expanded === p.name
                      ? <ChevronUp className="w-3.5 h-3.5" />
                      : <ChevronDown className="w-3.5 h-3.5" />
                    }
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs font-medium text-gray-800 dark:text-gray-200">{p.name}</td>
                  <td className="px-3 py-2.5 text-gray-600 dark:text-gray-300 max-w-[280px] truncate">{p.description}</td>
                  <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 tabular-nums">{p.push_interval_s}s</td>
                  <td className="px-3 py-2.5" onClick={(e) => e.stopPropagation()}>
                    <div className="space-y-1">
                      <Button size="sm" variant="primary" onClick={() => { setApplyTarget(p); setAgentId('') }}>
                        Appliquer
                      </Button>
                      {result[p.name] && (
                        <p className="text-xs text-green-600 dark:text-green-400">
                          Appliqué à {result[p.name].pushedTo}
                        </p>
                      )}
                    </div>
                  </td>
                </tr>
                {expanded === p.name && (
                  <tr key={`${p.name}-detail`}>
                    <td colSpan={5} className="p-0">
                      <ProfileDetail profile={p} />
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>

      {applyTarget && (
        <ActionModal
          title={`Appliquer « ${applyTarget.name} »`}
          message="Laisser le champ vide pour appliquer à tous les agents connus."
          confirmLabel="Appliquer"
          confirmVariant="primary"
          onConfirm={handleApply}
          onCancel={() => setApplyTarget(null)}
          loading={applying}
        >
          <div className="space-y-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">Agent ID (optionnel)</label>
            <Input
              type="text"
              placeholder="UUID de l'agent…"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              className="w-full font-mono"
            />
          </div>
        </ActionModal>
      )}
    </div>
  )
}
