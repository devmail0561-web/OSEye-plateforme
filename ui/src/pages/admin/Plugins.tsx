import { useState, useEffect, useCallback, useRef } from 'react'
import { Puzzle, Upload, ShieldCheck, ShieldOff } from 'lucide-react'
import { pluginsApi } from '@/api/client'
import type { PluginInfo } from '@/types'
import { Badge, Button, EmptyState, Spinner } from '@/components/ui'
import ActionModal from '@/components/admin/ActionModal'

function SignatureStatus() {
  const [cfg, setCfg] = useState<{ require_signature: boolean; has_trusted_keys: boolean } | null>(null)

  useEffect(() => {
    pluginsApi.config().then(setCfg).catch(() => {})
  }, [])

  if (!cfg) return null

  if (cfg.require_signature && cfg.has_trusted_keys) {
    return (
      <span className="flex items-center gap-1 text-green-600 dark:text-green-400 whitespace-nowrap">
        <ShieldCheck className="w-3.5 h-3.5" />
        Signature requise
      </span>
    )
  }
  if (cfg.require_signature && !cfg.has_trusted_keys) {
    return (
      <span className="flex items-center gap-1 text-red-500 whitespace-nowrap">
        <ShieldOff className="w-3.5 h-3.5" />
        Signature requise — aucune clé configurée
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1 text-amber-500 whitespace-nowrap">
      <ShieldOff className="w-3.5 h-3.5" />
      Signature non requise
    </span>
  )
}

function statusVariant(status: string): 'green' | 'default' | 'red' {
  if (status === 'running') return 'green'
  if (status === 'error')   return 'red'
  return 'default'
}

export default function Plugins() {
  const [plugins, setPlugins] = useState<PluginInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<PluginInfo | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await pluginsApi.list()
      setPlugins(data)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load() }, [load])

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    if (!file.name.endsWith('.py')) {
      setUploadError('Le fichier doit être un .py')
      return
    }
    setUploading(true)
    setUploadError('')
    try {
      const info = await pluginsApi.upload(file)
      setPlugins((prev) => [...prev, { name: info.name, status: info.status, pid: null, error: null }])
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Erreur lors de l\'installation'
      setUploadError(msg)
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function handleEnable(name: string) {
    setActionLoading(name)
    try {
      const updated = await pluginsApi.enable(name)
      setPlugins((prev) => prev.map((p) => p.name === name ? { ...p, status: updated.status, pid: updated.pid ?? null } : p))
    } finally {
      setActionLoading(null)
    }
  }

  async function handleDisable(name: string) {
    setActionLoading(name)
    try {
      const updated = await pluginsApi.disable(name)
      setPlugins((prev) => prev.map((p) => p.name === name ? { ...p, status: updated.status } : p))
    } finally {
      setActionLoading(null)
    }
  }

  async function handleDelete() {
    if (!confirmDelete) return
    setActionLoading(confirmDelete.name)
    setConfirmDelete(null)
    try {
      await pluginsApi.delete(confirmDelete.name)
      setPlugins((prev) => prev.filter((p) => p.name !== confirmDelete.name))
    } finally {
      setActionLoading(null)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Plugins</h1>
        <div className="flex items-center gap-2">
          {uploadError && <p className="text-xs text-red-400">{uploadError}</p>}
          <input
            ref={fileInputRef}
            type="file"
            accept=".py"
            className="hidden"
            onChange={handleUpload}
          />
          <Button
            variant="primary"
            size="sm"
            disabled={uploading}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="w-3.5 h-3.5" />
            {uploading ? 'Installation…' : 'Installer un plugin'}
          </Button>
        </div>
      </div>

      <div className="flex items-start gap-3 bg-gray-50 dark:bg-gray-900/50 border border-gray-200 dark:border-gray-700 rounded-xl p-3 text-xs text-gray-500 dark:text-gray-400">
        <div className="flex-1">
          Un plugin est un fichier <span className="font-mono">.py</span> implémentant <span className="font-mono">AnalyzerPlugin</span>, <span className="font-mono">ExporterPlugin</span> ou <span className="font-mono">CollectorPlugin</span> du SDK OSEye. Taille max : 1 Mo.
        </div>
        <SignatureStatus />
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Nom</th>
              <th className="text-left px-3 py-2.5">Statut</th>
              <th className="text-left px-3 py-2.5">PID</th>
              <th className="text-left px-3 py-2.5">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={4} />}
            {!loading && plugins.length === 0 && (
              <tr>
                <td colSpan={4}>
                  <EmptyState
                    icon={Puzzle}
                    title="Aucun plugin installé"
                    description="Cliquez sur « Installer un plugin » pour uploader un fichier .py"
                  />
                </td>
              </tr>
            )}
            {plugins.map((p) => {
              const busy = actionLoading === p.name
              return (
                <tr key={p.name} className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40">
                  <td className="px-3 py-2.5 font-mono text-xs text-gray-800 dark:text-gray-200">{p.name}</td>
                  <td className="px-3 py-2.5">
                    <div className="space-y-0.5">
                      <Badge variant={statusVariant(p.status)}>{p.status}</Badge>
                      {p.error && (
                        <p className="text-xs text-red-400 max-w-[200px] truncate" title={p.error}>{p.error}</p>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 tabular-nums font-mono text-xs">
                    {p.pid ?? '—'}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex gap-1">
                      {p.status !== 'running' && (
                        <Button size="sm" variant="ghost" disabled={busy} onClick={() => handleEnable(p.name)}>
                          {busy ? '…' : 'Activer'}
                        </Button>
                      )}
                      {p.status === 'running' && (
                        <Button size="sm" variant="ghost" disabled={busy} onClick={() => handleDisable(p.name)}>
                          {busy ? '…' : 'Désactiver'}
                        </Button>
                      )}
                      <Button size="sm" variant="danger" disabled={busy} onClick={() => setConfirmDelete(p)}>
                        Supprimer
                      </Button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {confirmDelete && (
        <ActionModal
          title="Supprimer le plugin"
          message={`Supprimer définitivement le plugin « ${confirmDelete.name} » ?`}
          confirmLabel="Supprimer"
          confirmVariant="danger"
          onConfirm={handleDelete}
          onCancel={() => setConfirmDelete(null)}
        />
      )}
    </div>
  )
}
