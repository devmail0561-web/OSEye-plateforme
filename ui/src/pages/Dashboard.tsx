import { useEffect } from 'react'
import { useTheme } from '@/hooks/useTheme'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { useAlertStore } from '@/stores/alertStore'
import { useEventStore } from '@/stores/eventStore'
import { Link } from 'react-router-dom'
import { SEVERITY_COLORS } from '@/lib/severityColors'

export default function Dashboard() {
  const { fetchStats, stats, openCount } = useAlertStore()
  const { rateHistory, eventsPerSecond } = useEventStore()
  const { isDark } = useTheme()

  const tooltipStyle = isDark
    ? { backgroundColor: '#111827', border: '1px solid #374151', color: '#f9fafb', fontSize: 12 }
    : { backgroundColor: '#fff', border: '1px solid #e5e7eb', color: '#111827', fontSize: 12 }
  const axisStroke = isDark ? '#374151' : '#d1d5db'
  const tickFill = isDark ? '#9ca3af' : '#6b7280'

  useEffect(() => {
    void fetchStats()
    const id = setInterval(() => void fetchStats(), 30_000)
    return () => clearInterval(id)
  }, [fetchStats])

  const severityData = stats
    ? Object.entries(stats.by_severity).map(([name, value]) => ({ name, value }))
    : []

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold text-gray-900 dark:text-white">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* KPI — Open alerts */}
        <Link
          to="/alerts?status=open"
          className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-5 hover:border-blue-300 dark:hover:border-blue-700 transition-colors group"
        >
          <p className="text-xs font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500">Alertes ouvertes</p>
          <p className="text-4xl font-bold text-gray-900 dark:text-white mt-2 tabular-nums">{openCount}</p>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-2 group-hover:text-blue-500 transition-colors">Voir toutes →</p>
        </Link>

        {/* KPI — Events/s */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500">Événements/s</p>
          <p className="text-4xl font-bold text-gray-900 dark:text-white mt-2 tabular-nums">{eventsPerSecond}</p>
          <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">Fenêtre 60s</p>
        </div>

        {/* Severity distribution */}
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-5">
          <p className="text-xs font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500 mb-3">Distribution sévérité</p>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={100}>
              <PieChart>
                <Pie
                  data={severityData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={45}
                >
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? '#6b7280'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex flex-wrap gap-2 mt-2">
              {(['critical','high','medium','low'] as const).map((sev) => (
                <span key={sev} className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-500">
                  <span className="w-2 h-2 rounded-full inline-block" style={{ background: SEVERITY_COLORS[sev] }} />
                  {sev}
                </span>
              ))}
              <p className="w-full text-xs text-gray-400 dark:text-gray-600 mt-1">Aucune alerte</p>
            </div>
          )}
        </div>
      </div>

      {/* Event rate chart */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-5">
        <p className="text-xs font-medium uppercase tracking-wide text-gray-400 dark:text-gray-500 mb-3">Taux d'événements (60 dernières secondes)</p>
        <ResponsiveContainer width="100%" height={160}>
          <LineChart data={rateHistory}>
            <XAxis dataKey="ts" tick={false} stroke={axisStroke} />
            <YAxis stroke={axisStroke} tick={{ fill: tickFill, fontSize: 11 }} width={30} />
            <Tooltip
              contentStyle={tooltipStyle}
              labelFormatter={() => ''}
              formatter={(v: number) => [`${v} ev/s`, 'Taux']}
            />
            <Line
              type="monotone"
              dataKey="rps"
              stroke="#60a5fa"
              strokeWidth={2}
              dot={false}
              isAnimationActive={false}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
