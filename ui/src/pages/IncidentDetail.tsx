import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ChevronLeft } from 'lucide-react'
import { incidentsApi } from '@/api/client'
import type { Incident, AlertSeverity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'
import CaseTimeline, { type TimelineEntry } from '@/components/CaseTimeline'
import { Badge } from '@/components/ui'

const STATUS_VARIANT: Record<string, 'red' | 'amber' | 'green'> = {
  open:          'red',
  investigating: 'amber',
  resolved:      'green',
}
const STATUS_LABELS: Record<string, string> = {
  open:          'Ouvert',
  investigating: 'Investigation',
  resolved:      'Résolu',
}

function fmtDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return h > 0 ? `${h}h ${m}m` : `${m}m`
}

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const [incident, setIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!id) return
    incidentsApi.getById(id)
      .then(setIncident)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return (
    <div className="p-6 text-sm text-gray-400 dark:text-gray-500">Chargement…</div>
  )
  if (!incident) return (
    <div className="p-6 text-sm text-red-400">Incident introuvable</div>
  )

  const timelineEntries: TimelineEntry[] = incident.timeline.map((ev) => ({
    id:        ev.alert_id,
    timestamp: ev.timestamp,
    label:     ev.title,
    detail:    `${ev.hostname} · ${ev.mitre_techniques.join(', ')}`,
    severity:  ev.severity,
  }))

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/incidents"
          className="inline-flex items-center gap-1 text-xs text-gray-400 dark:text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors mb-2"
        >
          <ChevronLeft className="w-3.5 h-3.5" /> Incidents
        </Link>
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white">{incident.hostname}</h1>
        <div className="flex items-center gap-2 mt-1.5">
          <SeverityBadge severity={incident.severity as AlertSeverity} />
          <Badge variant={STATUS_VARIANT[incident.status] ?? 'default'}>
            {STATUS_LABELS[incident.status] ?? incident.status}
          </Badge>
          <span className="text-xs text-gray-400 dark:text-gray-500">
            <RelativeTime iso={incident.created_at} />
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Alertes',      value: incident.alert_count },
          { label: 'Durée',        value: fmtDuration(incident.timeframe_seconds) },
          { label: 'Corrélation',  value: incident.correlation_rule },
          { label: 'MITRE',        value: incident.mitre_tactics.length },
        ].map(({ label, value }) => (
          <div key={label} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-400 dark:text-gray-500">{label}</p>
            <p className="text-lg font-bold text-gray-900 dark:text-white mt-0.5 truncate">{value}</p>
          </div>
        ))}
      </div>

      {incident.mitre_tactics.length > 0 && (
        <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
          <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Tactiques MITRE ATT&CK</p>
          <div className="flex flex-wrap gap-1.5">
            {incident.mitre_tactics.map((t) => (
              <span key={t} className="text-xs bg-gray-200 dark:bg-gray-800 text-gray-700 dark:text-gray-300 px-2 py-1 rounded font-mono">{t}</span>
            ))}
          </div>
        </div>
      )}

      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
        <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-3">Chronologie des alertes</p>
        <CaseTimeline entries={timelineEntries} />
      </div>

      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
        <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
          {incident.alert_ids.length} alerte{incident.alert_ids.length !== 1 ? 's' : ''} liée{incident.alert_ids.length !== 1 ? 's' : ''}
        </p>
        <div className="flex flex-wrap gap-1">
          {incident.alert_ids.map((aid) => (
            <Link
              key={aid}
              to={`/alerts?alert_id=${aid}`}
              className="text-xs font-mono text-blue-500 hover:text-blue-400 bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded transition-colors"
            >
              {aid.slice(0, 12)}…
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
