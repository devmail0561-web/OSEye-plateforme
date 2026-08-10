import { useState, useEffect } from 'react'

function format(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60) return `${diff}s`
  if (diff < 3600) return `${Math.floor(diff / 60)}m`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`
  return `${Math.floor(diff / 86400)}j`
}

export default function RelativeTime({ iso }: { iso: string }) {
  const [label, setLabel] = useState(() => format(iso))

  useEffect(() => {
    const id = setInterval(() => setLabel(format(iso)), 10_000)
    return () => clearInterval(id)
  }, [iso])

  return (
    <time dateTime={iso} title={iso} className="text-gray-400 dark:text-gray-400 tabular-nums">
      {label}
    </time>
  )
}
