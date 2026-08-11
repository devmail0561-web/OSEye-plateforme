const scoreColor = (s: number) =>
  s >= 0.8 ? 'text-red-400' : s >= 0.5 ? 'text-orange-300' : 'text-green-400'

export default function ScoreBar({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-gray-400 dark:text-gray-500 w-14 shrink-0">{label}</span>
      <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
        <div
          className="h-1.5 rounded-full bg-blue-500 transition-all"
          style={{ width: `${Math.min(value * 100, 100)}%` }}
        />
      </div>
      <span className={`w-10 text-right tabular-nums font-mono ${scoreColor(value)}`}>
        {(value * 100).toFixed(0)}%
      </span>
    </div>
  )
}
