import { useState, useEffect, useCallback, useRef } from 'react'
import { useLocation } from 'react-router-dom'
import { AlertTriangle, Copy, Check, X } from 'lucide-react'
import { apiKeysApi } from '@/api/client'
import type { ApiKeyResponse, ApiKeyCreate } from '@/types'
import { Badge, Button, Input, Select, Spinner, EmptyState } from '@/components/ui'
import { Key } from 'lucide-react'
import RelativeTime from '@/components/RelativeTime'

interface CreatedBanner {
  key: string
  key_id: string
  name: string
}

export default function ApiKeys() {
  const location = useLocation()
  const [keys, setKeys] = useState<ApiKeyResponse[]>([])
  const [loading, setLoading] = useState(false)
  const [showRevoked, setShowRevoked] = useState(false)
  const [banner, setBanner] = useState<CreatedBanner | null>(null)
  const [copied, setCopied] = useState(false)
  const keyInputRef = useRef<HTMLInputElement>(null)

  // Form state
  const [name, setName] = useState('')
  const [role, setRole] = useState('analyst')
  const [expiresAt, setExpiresAt] = useState('')
  const [creating, setCreating] = useState(false)
  const [createError, setCreateError] = useState('')

  const load = useCallback(async (includeRevoked: boolean) => {
    setLoading(true)
    try {
      const data = await apiKeysApi.list(includeRevoked)
      setKeys(data.items)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { void load(showRevoked) }, [load, showRevoked])

  useEffect(() => { setBanner(null) }, [location.pathname])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    setCreateError('')
    try {
      const body: ApiKeyCreate = {
        name: name.trim(),
        roles: [role],
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      }
      const created = await apiKeysApi.create(body)
      setBanner({ key: created.key, key_id: created.key_id, name: created.name })
      setKeys((prev) => [...prev, {
        key_id:     created.key_id,
        name:       created.name,
        roles:      created.roles,
        created_by: '',
        expires_at: body.expires_at ?? null,
        revoked:    false,
      }])
      setName('')
      setExpiresAt('')
    } catch {
      setCreateError('Erreur lors de la création')
    } finally {
      setCreating(false)
    }
  }

  async function handleCopy() {
    if (!banner) return
    if (navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(banner.key)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        return
      } catch { /* fallback */ }
    }
    keyInputRef.current?.select()
  }

  async function handleRevoke(key_id: string) {
    await apiKeysApi.revoke(key_id)
    if (showRevoked) {
      // Mettre à jour le statut en place (la ligne reste visible car on affiche les révoquées)
      setKeys((prev) => prev.map((k) => k.key_id === key_id ? { ...k, revoked: true } : k))
    } else {
      // Masquer la ligne (comportement par défaut)
      setKeys((prev) => prev.filter((k) => k.key_id !== key_id))
    }
  }

  const revokedCount = keys.filter((k) => k.revoked).length

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">API Keys</h1>

      {/* Created key banner */}
      {banner && (
        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-xl p-4 space-y-3">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                Clé <span className="font-mono">{banner.name}</span> créée — copiez-la maintenant
              </p>
              <p className="text-xs text-amber-700 dark:text-amber-400 mt-0.5">
                Elle ne sera plus affichée après la fermeture de cette bannière.
              </p>
            </div>
            <button onClick={() => setBanner(null)} className="text-amber-600 dark:text-amber-400 hover:text-amber-800 dark:hover:text-amber-200">
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="flex gap-2">
            <input
              ref={keyInputRef}
              readOnly
              value={banner.key}
              className="flex-1 font-mono text-xs bg-amber-100 dark:bg-amber-900/40 border border-amber-300 dark:border-amber-700 rounded px-2.5 py-1.5 text-amber-900 dark:text-amber-100 select-all"
              onFocus={(e) => e.target.select()}
            />
            <Button size="sm" variant="ghost" onClick={handleCopy}
              className="shrink-0 bg-amber-100 hover:bg-amber-200 text-amber-800 dark:bg-amber-900/40 dark:hover:bg-amber-900 dark:text-amber-200"
            >
              {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              {copied ? 'Copié' : 'Copier'}
            </Button>
          </div>
        </div>
      )}

      {/* Create form */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
        <h2 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">Créer une clé</h2>
        <form onSubmit={handleCreate} className="flex flex-wrap gap-2 items-end">
          <div className="flex-1 min-w-[160px] space-y-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">Nom</label>
            <Input required placeholder="ex. agent-prod-01" value={name}
              onChange={(e) => setName(e.target.value)} className="w-full" />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">Rôle</label>
            <Select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </Select>
          </div>
          <div className="space-y-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">Expire le (optionnel)</label>
            <Input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
          </div>
          <Button type="submit" variant="primary" size="sm" disabled={creating}>
            {creating ? 'Création…' : 'Créer'}
          </Button>
        </form>
        {createError && <p className="text-xs text-red-400 mt-2">{createError}</p>}
      </div>

      {/* Keys table */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        {/* Toolbar */}
        <div className="flex items-center justify-between px-3 py-2 border-b border-gray-100 dark:border-gray-800">
          <span className="text-xs text-gray-400 dark:text-gray-500">
            {keys.filter((k) => !k.revoked).length} clé{keys.filter((k) => !k.revoked).length !== 1 ? 's' : ''} active{keys.filter((k) => !k.revoked).length !== 1 ? 's' : ''}
            {showRevoked && revokedCount > 0 && ` · ${revokedCount} révoquée${revokedCount > 1 ? 's' : ''}`}
          </span>
          <label className="flex items-center gap-1.5 text-xs text-gray-500 dark:text-gray-400 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showRevoked}
              onChange={(e) => setShowRevoked(e.target.checked)}
              className="accent-blue-500"
            />
            Afficher les révoquées
          </label>
        </div>

        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">Nom</th>
              <th className="text-left px-3 py-2.5">Rôles</th>
              <th className="text-left px-3 py-2.5">Créé par</th>
              <th className="text-left px-3 py-2.5">Expire le</th>
              <th className="text-left px-3 py-2.5">Statut</th>
              <th className="text-left px-3 py-2.5">Action</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={6} />}
            {!loading && keys.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <EmptyState icon={Key} title="Aucune clé API"
                    description="Créez une clé pour permettre à un agent de s'authentifier" />
                </td>
              </tr>
            )}
            {keys.map((k) => (
              <tr
                key={k.key_id}
                className={`border-b border-gray-100 dark:border-gray-800/50 ${
                  k.revoked
                    ? 'opacity-50'
                    : 'hover:bg-gray-50 dark:hover:bg-gray-800/40'
                }`}
              >
                <td className="px-3 py-2.5 font-medium font-mono text-xs text-gray-800 dark:text-gray-200">
                  {k.name}
                </td>
                <td className="px-3 py-2.5">
                  <div className="flex gap-1">
                    {k.roles.map((r) => (
                      <Badge key={r} variant={r === 'admin' ? 'red' : 'blue'}>{r}</Badge>
                    ))}
                  </div>
                </td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 text-xs">{k.created_by}</td>
                <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400 text-xs">
                  {!k.revoked && k.expires_at ? <RelativeTime iso={k.expires_at} /> : '—'}
                </td>
                <td className="px-3 py-2.5">
                  <Badge variant={k.revoked ? 'default' : 'green'}>
                    {k.revoked ? 'Révoquée' : 'Active'}
                  </Badge>
                </td>
                <td className="px-3 py-2.5">
                  {!k.revoked && (
                    <Button size="sm" variant="danger" onClick={() => handleRevoke(k.key_id)}>
                      Révoquer
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
