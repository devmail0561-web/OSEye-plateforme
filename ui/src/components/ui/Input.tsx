import type { InputHTMLAttributes } from 'react'

type InputProps = InputHTMLAttributes<HTMLInputElement>

export default function Input({ className = '', ...rest }: InputProps) {
  return (
    <input
      className={`bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2.5 py-1.5 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-600 ${className}`}
      {...rest}
    />
  )
}
