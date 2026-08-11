import type { ReactNode } from 'react'
import { X } from 'lucide-react'
import { Button } from '@/components/ui'

interface Props {
  title: string
  message?: string
  confirmLabel?: string
  confirmVariant?: 'primary' | 'danger' | 'ghost'
  onConfirm: () => void
  onCancel: () => void
  loading?: boolean
  children?: ReactNode
}

export default function ActionModal({
  title,
  message,
  confirmLabel = 'Confirmer',
  confirmVariant = 'primary',
  onConfirm,
  onCancel,
  loading = false,
  children,
}: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl shadow-xl p-6 w-full max-w-sm space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-900 dark:text-white">{title}</h2>
          <button
            onClick={onCancel}
            className="text-gray-400 hover:text-gray-700 dark:hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {message && (
          <p className="text-sm text-gray-600 dark:text-gray-300">{message}</p>
        )}

        {children}

        <div className="flex justify-end gap-2 pt-1">
          <Button variant="ghost" onClick={onCancel} disabled={loading}>
            Annuler
          </Button>
          <Button variant={confirmVariant} onClick={onConfirm} disabled={loading}>
            {loading ? 'En cours…' : confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  )
}
