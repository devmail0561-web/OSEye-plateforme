import { useCountdown } from '@/hooks/useCountdown'

function fmt(s: number): string {
  if (s <= 0) return 'Expiré'
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  return `${Math.floor(s / 3600)}h`
}

export default function CountdownBadge({ iso }: { iso: string }) {
  const { remaining, expired } = useCountdown(iso)
  return (
    <span className={`text-xs tabular-nums font-mono ${expired ? 'text-red-400' : 'text-amber-400'}`}>
      {fmt(remaining)}
    </span>
  )
}
