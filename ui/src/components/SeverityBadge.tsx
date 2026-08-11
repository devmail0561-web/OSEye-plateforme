import type { Severity, AlertSeverity } from '@/types'

const STYLES: Record<string, string> = {
  info:     'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
  low:      'bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-200',
  medium:   'bg-amber-100 text-amber-800 dark:bg-amber-900/60 dark:text-amber-200',
  high:     'bg-orange-100 text-orange-800 dark:bg-orange-900/60 dark:text-orange-200',
  critical: 'bg-red-100 text-red-800 dark:bg-red-900/60 dark:text-red-200',
}

interface Props {
  severity: Severity | AlertSeverity
  className?: string
}

export default function SeverityBadge({ severity, className = '' }: Props) {
  return (
    <span
      className={`inline-block text-xs font-medium px-1.5 py-0.5 rounded ${STYLES[severity] ?? 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300'} ${className}`}
    >
      {severity}
    </span>
  )
}
