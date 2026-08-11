import { Loader2 } from 'lucide-react'

interface SpinnerProps {
  colSpan?: number
}

export default function Spinner({ colSpan }: SpinnerProps) {
  const inner = (
    <span className="flex items-center justify-center gap-2 text-gray-400 dark:text-gray-500 text-sm py-12">
      <Loader2 className="w-4 h-4 animate-spin" />
      Chargement…
    </span>
  )

  if (colSpan !== undefined) {
    return (
      <tr>
        <td colSpan={colSpan} className="text-center">
          {inner}
        </td>
      </tr>
    )
  }

  return inner
}
