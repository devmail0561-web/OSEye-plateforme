interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'blue' | 'amber' | 'green' | 'red' | 'orange' | 'slate'
  className?: string
}

const VARIANTS: Record<NonNullable<BadgeProps['variant']>, string> = {
  default: 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-300',
  blue:    'bg-blue-100 text-blue-800 dark:bg-blue-900/60 dark:text-blue-200',
  amber:   'bg-amber-100 text-amber-800 dark:bg-amber-900/60 dark:text-amber-200',
  green:   'bg-green-100 text-green-800 dark:bg-green-900/60 dark:text-green-200',
  red:     'bg-red-100 text-red-800 dark:bg-red-900/60 dark:text-red-200',
  orange:  'bg-orange-100 text-orange-800 dark:bg-orange-900/60 dark:text-orange-200',
  slate:   'bg-slate-200 text-slate-700 dark:bg-slate-700 dark:text-slate-200',
}

export default function Badge({ children, variant = 'default', className = '' }: BadgeProps) {
  return (
    <span className={`inline-block text-xs font-medium px-1.5 py-0.5 rounded ${VARIANTS[variant]} ${className}`}>
      {children}
    </span>
  )
}
