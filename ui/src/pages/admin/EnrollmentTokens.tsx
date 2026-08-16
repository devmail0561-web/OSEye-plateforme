import { useState, useEffect, useCallback, useRef } from 'react'
import { AlertTriangle, Copy, Check, X, Plus, Ticket } from 'lucide-react'
import { enrollmentApi } from '@/api/client'
import type { EnrollmentToken } from '@/api/client'
import { Badge, Button, EmptyState, Input, Spinner } from '@/components/ui'
import RelativeTime from '@/components/RelativeTime'

function expiresVariant(expiresAt: string): 'red' | 'yellow' | 'green' {
  const ms = new Date(expiresAt).getTime() - Date.now()
  if (ms < 3_600_000) return 'red'
  if (ms < 21_600_000) return 'yellow'
  return 'green'
}

export default function EnrollmentTokens() {
  const [tokens, setTokens]     = useState<EnrollmentToken[]>([])
  const [loading, setLoading]   = useState(false)
  const [creating, setCreating] = useState(false)
  const [ttlHours, setTtlHours]   = useState<string>('24')
  const [banner, setBanner]       = useState<{ token: string; token_id: string } | null>(null)
  const [copied, setCopied]       = useState(false)
  const [createError, setCreateError] = useState('')
  const [revokeError, setRevokeError] = useState('')
  const tokenInputRef = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try { setTokens(await enrollmentApi.list()) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { void load() }, [load])

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    const hours = parseInt(ttlHours, 10)
    if (!hours || hours < 1 || hours > 8760) return
    setCreating(true)
    setCreateError('')
    try {
      const result = await enrollmentApi.create(hours)
      setBanner(result)
      void load()
    } catch {
      setCreateError('Erreur lors de la génération du token')
    } finally {
      setCreating(false)
    }
  }

  async function handleCopy() {
    if (!banner) return
    if (navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(banner.token)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        return
      } catch { /* fallback */ }
    }
    tokenInputRef.current?.select()
  }

  async function handleRevoke(token_id: string) {
    setRevokeError('')
    try {
      await enrollmentApi.revoke(token_id)
      setTokens((prev) => prev.filter((t) => t.token_id !== token_id))
      if (banner?.token_id === token_id) setBanner(null)
    } catch {
      setRevokeError('Erreur lors de la révocation')
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
        Tokens d&apos;enrollment
      </h1>

      {/* Created token banner */}
      {banner && (
        <div className="bg-amber-50 dark:bg-amber-900/20 border border-amber-300 dark:border-amber-700 rounded-xl p-4 space-y-3">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
                Token généré — copiez-le maintenant
              </p>
              <p className="text-xs text-amber-700 dark:text-amber-400 mt-0.5">
                Injectez-le via{' '}
                <code className="font-mono">OSEYE_ENROLL_TOKEN</code> sur l&apos;hôte de l&apos;agent.
                Il ne sera plus affiché après la fermeture.
              </p>
            </div>
            <button
              onClick={() => setBanner(null)}
              className="text-amber-600 dark:text-amber-400 hover:text-amber-800 dark:hover:text-amber-200"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
          <div className="flex gap-2">
            <input
              ref={tokenInputRef}
              readOnly
              value={banner.token}
              className="flex-1 font-mono text-xs bg-amber-100 dark:bg-amber-900/40 border border-amber-300 dark:border-amber-700 rounded px-2.5 py-1.5 text-amber-900 dark:text-amber-100 select-all"
              onFocus={(e) => e.target.select()}
            />
            <Button
              size="sm" variant="ghost" onClick={handleCopy}
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
        <h2 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
          Générer un token
        </h2>
        <form onSubmit={handleCreate} className="flex flex-wrap gap-2 items-end">
          <div className="space-y-1">
            <label className="text-xs text-gray-500 dark:text-gray-400">
              Durée de validité (heures)
            </label>
            <Input
              type="number"
              min={1}
              max={8760}
              value={ttlHours}
              onChange={(e) => setTtlHours(e.target.value)}
              className="w-32"
            />
          </div>
          <Button type="submit" variant="primary" size="sm" disabled={creating}>
            <Plus className="w-4 h-4" />
            {creating ? 'Génération…' : 'Générer'}
          </Button>
        </form>
        <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">
          Défaut serveur : <code className="font-mono">OSEYE_ENROLLMENT_TOKEN_DEFAULT_TTL_HOURS</code>.
          Max : 8 760 h (1 an).
        </p>
        {createError && <p className="text-xs text-red-500 mt-1">{createError}</p>}
      </div>

      {/* Tokens table */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl overflow-x-auto">
        <div className="px-3 py-2 border-b border-gray-100 dark:border-gray-800">
          <span className="text-xs text-gray-400 dark:text-gray-500">
            {tokens.length} token{tokens.length !== 1 ? 's' : ''} actif{tokens.length !== 1 ? 's' : ''}
            &nbsp;· usage unique · stockés comme hash HMAC-SHA256
          </span>
        </div>

        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-800 text-gray-400 dark:text-gray-500 text-xs uppercase">
              <th className="text-left px-3 py-2.5">ID</th>
              <th className="text-left px-3 py-2.5">Créé par</th>
              <th className="text-left px-3 py-2.5">Créé le</th>
              <th className="text-left px-3 py-2.5">Expire le</th>
              <th className="text-left px-3 py-2.5">Action</th>
            </tr>
          </thead>
          <tbody>
            {loading && <Spinner colSpan={5} />}
            {!loading && tokens.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <EmptyState
                    icon={Ticket}
                    title="Aucun token actif"
                    description="Générez un token pour enrôler un nouvel agent"
                  />
                </td>
              </tr>
            )}
            {tokens.map((t) => (
              <tr
                key={t.token_id}
                className="border-b border-gray-100 dark:border-gray-800/50 hover:bg-gray-50 dark:hover:bg-gray-800/40"
              >
                <td className="px-3 py-2.5 font-mono text-xs text-gray-500 dark:text-gray-400">
                  {t.token_id.slice(0, 8)}…
                </td>
                <td className="px-3 py-2.5 text-xs text-gray-600 dark:text-gray-300">
                  {t.created_by}
                </td>
                <td className="px-3 py-2.5 text-xs text-gray-500 dark:text-gray-400">
                  <RelativeTime iso={t.created_at} />
                </td>
                <td className="px-3 py-2.5">
                  <Badge variant={expiresVariant(t.expires_at)}>
                    <RelativeTime iso={t.expires_at} />
                  </Badge>
                </td>
                <td className="px-3 py-2.5">
                  <Button size="sm" variant="danger" onClick={() => handleRevoke(t.token_id)}>
                    Révoquer
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {revokeError && <p className="text-xs text-red-500">{revokeError}</p>}
    </div>
  )
}
