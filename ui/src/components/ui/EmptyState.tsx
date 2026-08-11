import type { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description?: string
}

export default function EmptyState({ icon: Icon, title, description }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-14 text-center">
      <Icon className="w-8 h-8 text-gray-400 dark:text-gray-600 mb-3" strokeWidth={1.5} />
      <p className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</p>
      {description && (
        <p className="text-xs text-gray-400 dark:text-gray-600 mt-1 max-w-xs">{description}</p>
      )}
    </div>
  )
}
