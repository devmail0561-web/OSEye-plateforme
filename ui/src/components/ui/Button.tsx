import type { ButtonHTMLAttributes } from 'react'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'ghost' | 'danger'
  size?: 'sm' | 'md'
}

const VARIANTS: Record<NonNullable<ButtonProps['variant']>, string> = {
  primary: 'bg-blue-600 hover:bg-blue-500 dark:bg-blue-700 dark:hover:bg-blue-600 text-white',
  ghost:   'bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300',
  danger:  'bg-red-100 hover:bg-red-200 text-red-800 dark:bg-red-900/50 dark:hover:bg-red-900 dark:text-red-200',
}

const SIZES: Record<NonNullable<ButtonProps['size']>, string> = {
  sm: 'px-2.5 py-1 text-xs',
  md: 'px-4 py-2 text-sm',
}

export default function Button({
  variant = 'ghost',
  size = 'md',
  className = '',
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={`inline-flex items-center gap-1.5 rounded font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${VARIANTS[variant]} ${SIZES[size]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  )
}
