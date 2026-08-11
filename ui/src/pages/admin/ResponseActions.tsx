import { useState, useEffect, useCallback } from 'react'
import { ShieldAlert } from 'lucide-react'
import { responseActionsApi, type ResponseAction } from '@/api/client'
import { Badge, Button, EmptyState, Spinner } from '@/components/ui'
import ActionModal from '@/components/admin/ActionModal'
import RelativeTime from '@/components/RelativeTime'

const STATUS_VARIANT: Record<ResponseAction['status'], 'amber' | 'red' | 'default' | 'green'> = {
  pending_report: 'amber',
  executed:       'red',
  failed:         'default',
  rolled_back:    'green',
}

const STATUS_LABELS: Record<ResponseAction['status'], string> = {
  pending_report: 'En attente',
  executed:       'Actif',
  failed:         'Échec',
  rolled_back:    'Annulé',
}

const TYPE_LABELS: Record<string, string> = {
  BLOCK_IP:        'Blocage IP',
  UNBLOCK_IP:      'Déblocage IP',
  QUARANTINE_FILE: 'Quarantaine fichier',
  RESTORE_FILE:    'Restauration fichier',
  KILL_PROCESS:    'Kill processus',
}

function actionTarget(action: ResponseAction): string {
  const p = action.payload
  if (p.ip)               return String(p.ip)
  if (p.path)             return String(p.path)
  if (p.pid)              return `PID ${p.pid} (${p.process_name ?? '?'})`
  if (p.quarantine_path)  return String(p.quarantine_path)
  return '—'
}

export default function ResponseActions() {
  const [actions, setActions] = useState<ResponseAction[]>([])
  const [loading, setLoading] = useState(false)
  const [rollbackTarget, setRollbackTarget] = useState<ResponseAction | null>(null)
  const [rolling, setRolling] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await responseActionsApi.list({ limit: 100 })
      setActions(data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function handleRollback() {
    if (!rollbackTarget) return
    setRolling(true)
    try {
      await responseActionsApi.rollback(rollbackTarget.command_id)
      setActions((prev) => prev.map((a) =>
        a.command_id === rollbackTarget.command_id
          ? { ...a, status: 'rolled_back' as const }
          : a
      ))
      setRollbackTarget(null)
    } finally {
      setRolling(false)
    }
  }

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Actions de réponse</h1>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Type</th>
              <th className="text-left px-3 py-2.5">Agent</th>
              <th className="text-left px-3 py-2.5">Cible</th>
              <th className="text-left px-3 py-2.5">Statut</th>
              <th className="text-left px-3 py-2.5">Déclenché</th>
              <th className="text-left px-3 py-2.5">Exécuté</th>
              <th className="text-left px-3 py-2.5">Action</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={7} />}
            {!loading && actions.length === 0 && (
              <tr>
                <td colSpan={7}>
                  <EmptyState
                    icon={ShieldAlert}
                    title="Aucune action de réponse"
                    description="Les actions déclenchées par le Decision Engine apparaîtront ici"
                  />
                </td>
              </tr>
            )}
            {actions.map((a) => (
              <tr key={a.command_id} className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40">
                <td className="px-3 py-2.5 font-medium text-gray-800 dark:text-gray-200">
                  {TYPE_LABELS[a.command_type] ?? a.command_type}
                </td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 font-mono text-xs">{a.agent_cn}</td>
                <td className="px-3 py-2.5 text-gray-600 dark:text-gray-300 font-mono text-xs max-w-[200px] truncate">
                  {actionTarget(a)}
                </td>
                <td className="px-3 py-2.5">
                  <Badge variant={STATUS_VARIANT[a.status]}>{STATUS_LABELS[a.status]}</Badge>
                </td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 text-xs">
                  <RelativeTime iso={a.created_at} />
                </td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 text-xs">
                  {a.executed_at ? <RelativeTime iso={a.executed_at} /> : '—'}
                </td>
                <td className="px-3 py-2.5">
                  {a.status === 'executed' && (a.command_type === 'BLOCK_IP' || a.command_type === 'QUARANTINE_FILE') && (
                    <Button size="sm" variant="ghost" onClick={() => setRollbackTarget(a)}>
                      Annuler
                    </Button>
                  )}
                  {a.status === 'failed' && a.error && (
                    <span className="text-xs text-red-400 max-w-[120px] truncate block" title={a.error}>
                      {a.error}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {rollbackTarget && (
        <ActionModal
          title="Annuler l'action"
          message={`Annuler ${TYPE_LABELS[rollbackTarget.command_type] ?? rollbackTarget.command_type} sur ${actionTarget(rollbackTarget)} (agent ${rollbackTarget.agent_cn}) ?`}
          confirmLabel="Annuler l'action"
          confirmVariant="danger"
          onConfirm={handleRollback}
          onCancel={() => setRollbackTarget(null)}
          loading={rolling}
        />
      )}
    </div>
  )
}
