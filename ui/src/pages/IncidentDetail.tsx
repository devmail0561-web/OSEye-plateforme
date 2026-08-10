import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { incidentsApi } from '@/api/client'
import type { Incident, AlertSeverity } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'
import CaseTimeline, { type TimelineEntry } from '@/components/CaseTimeline'

const STATUS_STYLES: Record<string, string> = {
  open: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  investigating: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  resolved: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
}

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>()
  const [incident, setIncident] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!id) return
    incidentsApi.getById(id)
      .then(setIncident)
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <p className="text-gray-400 dark:text-gray-500 text-sm p-6">Chargement…</p>
  if (!incident) return <p className="text-red-400 text-sm p-6">Incident introuvable</p>

  const timelineEntries: TimelineEntry[] = incident.timeline.map((ev) => ({
    id: ev.alert_id,
    timestamp: ev.timestamp,
    label: ev.title,
    detail: `${ev.hostname} · ${ev.mitre_techniques.join(', ')}`,
    severity: ev.severity,
  }))

  const durationMin = Math.round(incident.timeframe_seconds / 60)

  return (
    <div className="space-y-6">
      <div>
        <Link to="/incidents" className="text-xs text-gray-400 dark:text-gray-500 hover:text-gray-400 dark:text-gray-400">← Incidents</Link>
        <h1 className="text-xl font-semibold text-gray-900 dark:text-white mt-1">{incident.hostname}</h1>
        <div className="flex items-center gap-2 mt-1">
          <SeverityBadge severity={incident.severity as AlertSeverity} />
          <span className={`text-xs px-1.5 py-0.5 rounded ${STATUS_STYLES[incident.status] ?? 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300'}`}>
            {incident.status}
          </span>
          <span className="text-xs text-gray-400 dark:text-gray-500">
            <RelativeTime iso={incident.created_at} />
          </span>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Alertes', value: incident.alert_count },
          { label: 'Durée', value: `${durationMin}min` },
          { label: 'Corrélation', value: incident.correlation_rule },
          { label: 'MITRE', value: incident.mitre_tactics.length },
        ].map(({ label, value }) => (
          <div key={label} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
            <p className="text-xs text-gray-400 dark:text-gray-500">{label}</p>
            <p className="text-lg font-bold text-gray-900 dark:text-white mt-0.5 truncate">{value}</p>
          </div>
        ))}
      </div>

      {/* MITRE tactics */}
      {incident.mitre_tactics.length > 0 && (
        <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-2">
          <p className="text-sm font-medium text-gray-400 dark:text-gray-400">Tactiques MITRE ATT&CK</p>
          <div className="flex flex-wrap gap-2">
            {incident.mitre_tactics.map((t) => (
              <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 px-2 py-1 rounded font-mono">{t}</span>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-3">
        <p className="text-sm font-medium text-gray-400 dark:text-gray-400">Chronologie des alertes</p>
        <CaseTimeline entries={timelineEntries} />
      </div>

      {/* Alert IDs */}
      <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-2">
        <p className="text-sm font-medium text-gray-400 dark:text-gray-400">{incident.alert_ids.length} alerte(s) liée(s)</p>
        <div className="flex flex-wrap gap-1">
          {incident.alert_ids.map((aid) => (
            <Link
              key={aid}
              to={`/alerts?alert_id=${aid}`}
              className="text-xs font-mono text-blue-400 hover:text-blue-300 bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded"
            >
              {aid.slice(0, 12)}…
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
