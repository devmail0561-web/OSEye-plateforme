import type { SelectHTMLAttributes } from 'react'

type SelectProps = SelectHTMLAttributes<HTMLSelectElement>

export default function Select({ className = '', children, ...rest }: SelectProps) {
  return (
    <select
      className={`bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2.5 py-1.5 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-600 ${className}`}
      {...rest}
    >
      {children}
    </select>
  )
}
