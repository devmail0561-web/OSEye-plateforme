import { useState } from 'react'
import { X } from 'lucide-react'
import { casesApi, type CaseCreateBody } from '@/api/client'
import type { ForensicCase, AlertSeverity } from '@/types'
import { Button, Input, Select } from '@/components/ui'

const SEVERITIES: AlertSeverity[] = ['low', 'medium', 'high', 'critical']

interface Props {
  onClose: () => void
  onCreate: (c: ForensicCase) => void
}

export default function NewCaseModal({ onClose, onCreate }: Props) {
  const [title, setTitle] = useState('')
  const [severity, setSeverity] = useState<AlertSeverity>('medium')
  const [description, setDescription] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!title.trim()) return
    setLoading(true)
    setError('')
    try {
      const body: CaseCreateBody = { title: title.trim(), severity, description }
      onCreate(await casesApi.create(body))
    } catch {
      setError('Erreur lors de la création')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl shadow-xl p-6 w-full max-w-md space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900 dark:text-white">Nouveau cas</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-700 dark:hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={submit} className="space-y-3">
          <Input
            required
            type="text"
            placeholder="Titre *"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full"
          />
          <Select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as AlertSeverity)}
            className="w-full"
          >
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </Select>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Description…"
            rows={3}
            className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2.5 py-1.5 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 resize-none focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          {error && <p className="text-xs text-red-400">{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <Button type="button" variant="ghost" onClick={onClose}>Annuler</Button>
            <Button type="submit" variant="primary" disabled={loading}>
              {loading ? 'Création…' : 'Créer'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
