import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { casesApi } from '@/api/client'
import type { ForensicCase, CaseStatus, AlertSeverity, EvidenceType } from '@/types'
import SeverityBadge from '@/components/SeverityBadge'
import RelativeTime from '@/components/RelativeTime'
import CaseTimeline, { type TimelineEntry } from '@/components/CaseTimeline'

const TABS = ['Aperçu', 'Preuves', 'Notes', 'Custody', 'Timeline'] as const
type Tab = (typeof TABS)[number]

const STATUS_STYLES: Record<CaseStatus, string> = {
  open: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  in_progress: 'bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200',
  resolved: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  archived: 'bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400',
}

const EVIDENCE_TYPES: EvidenceType[] = ['event', 'file_hash', 'screenshot', 'note', 'external']

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export default function CaseDetail() {
  const { id } = useParams<{ id: string }>()
  const [cas, setCas] = useState<ForensicCase | null>(null)
  const [loading, setLoading] = useState(true)
  const [tab, setTab] = useState<Tab>('Aperçu')

  // Evidence add form
  const [evType, setEvType] = useState<EvidenceType>('note')
  const [evContent, setEvContent] = useState('')
  const [evDesc, setEvDesc] = useState('')
  const [evLoading, setEvLoading] = useState(false)

  // Note add form
  const [noteContent, setNoteContent] = useState('')
  const [noteLoading, setNoteLoading] = useState(false)

  // Close form
  const [resolution, setResolution] = useState('')
  const [closeLoading, setCloseLoading] = useState(false)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    casesApi.getById(id)
      .then(setCas)
      .finally(() => setLoading(false))
  }, [id])

  async function addEvidence(e: React.FormEvent) {
    e.preventDefault()
    if (!id || !evContent.trim()) return
    setEvLoading(true)
    try {
      const item = await casesApi.addEvidence(id, { type: evType, content: evContent, description: evDesc || undefined })
      setCas((prev) => prev ? { ...prev, evidence: [...prev.evidence, item] } : prev)
      setEvContent('')
      setEvDesc('')
    } finally {
      setEvLoading(false)
    }
  }

  async function addNote(e: React.FormEvent) {
    e.preventDefault()
    if (!id || !noteContent.trim()) return
    setNoteLoading(true)
    try {
      const note = await casesApi.addNote(id, noteContent)
      setCas((prev) => prev ? { ...prev, notes: [...prev.notes, note] } : prev)
      setNoteContent('')
    } finally {
      setNoteLoading(false)
    }
  }

  async function closeCase() {
    if (!id) return
    setCloseLoading(true)
    try {
      const updated = await casesApi.close(id, resolution)
      setCas(updated)
    } finally {
      setCloseLoading(false)
    }
  }

  async function exportFile(format: 'json' | 'html' | 'pdf') {
    if (!id) return
    const fn = format === 'json' ? casesApi.exportJson : format === 'html' ? casesApi.exportHtml : casesApi.exportPdf
    const blob = await fn(id)
    downloadBlob(blob, `case-${id}.${format}`)
  }

  if (loading) {
    return <p className="text-gray-400 dark:text-gray-500 text-sm p-6">Chargement…</p>
  }
  if (!cas) {
    return <p className="text-red-400 text-sm p-6">Cas introuvable</p>
  }

  const timelineEntries: TimelineEntry[] = cas.notes.map((n) => ({
    id: n.note_id,
    timestamp: n.created_at,
    label: `Note de ${n.author}`,
    detail: n.content,
  })).concat(
    cas.evidence.map((ev) => ({
      id: ev.evidence_id,
      timestamp: ev.added_at,
      label: `Preuve ajoutée — ${ev.type}`,
      detail: ev.description ?? ev.content.slice(0, 80),
    }))
  ).sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())

  const severities: AlertSeverity[] = ['low', 'medium', 'high', 'critical']

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <Link to="/cases" className="text-xs text-gray-400 dark:text-gray-500 hover:text-gray-400 dark:text-gray-400">← Cas</Link>
          <h1 className="text-xl font-semibold text-gray-900 dark:text-white mt-1">{cas.title}</h1>
          <div className="flex items-center gap-2 mt-1">
            <SeverityBadge severity={cas.severity} />
            <span className={`text-xs px-1.5 py-0.5 rounded ${STATUS_STYLES[cas.status]}`}>
              {cas.status}
            </span>
            <span className="text-xs text-gray-400 dark:text-gray-500">
              par {cas.created_by} · <RelativeTime iso={cas.created_at} />
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {['json', 'html', 'pdf'].map((fmt) => (
            <button
              key={fmt}
              onClick={() => exportFile(fmt as 'json' | 'html' | 'pdf')}
              className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-800 hover:bg-gray-300 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300 rounded"
            >
              {fmt.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-200 dark:border-gray-800">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm -mb-px border-b-2 transition-colors ${
              tab === t
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-400 dark:text-gray-400 hover:text-gray-700 dark:text-gray-300'
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'Aperçu' && (
        <div className="space-y-4">
          <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-2 text-sm">
            {cas.description && <p className="text-gray-700 dark:text-gray-300">{cas.description}</p>}
            <div className="grid grid-cols-2 gap-2 text-xs text-gray-400 dark:text-gray-400">
              <p><span className="text-gray-400 dark:text-gray-500">Assigné :</span> {cas.assigned_to ?? '—'}</p>
              <p><span className="text-gray-400 dark:text-gray-500">Alertes :</span> {cas.alert_ids.length}</p>
              <p><span className="text-gray-400 dark:text-gray-500">Événements :</span> {cas.event_ids.length}</p>
              <p><span className="text-gray-400 dark:text-gray-500">Preuves :</span> {cas.evidence.length}</p>
            </div>
            {cas.tags.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {cas.tags.map((t) => (
                  <span key={t} className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400 px-1.5 py-0.5 rounded">{t}</span>
                ))}
              </div>
            )}
          </div>

          {cas.status !== 'resolved' && cas.status !== 'archived' && (
            <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-3">
              <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Clôturer le cas</p>
              <div className="flex gap-2">
                <select
                  value={resolution}
                  onChange={(e) => setResolution(e.target.value)}
                  className="flex-1 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1.5 text-sm text-gray-900 dark:text-white"
                >
                  <option value="">Résolution…</option>
                  <option value="true_positive">Vrai positif</option>
                  <option value="false_positive">Faux positif</option>
                  <option value="benign">Bénin</option>
                  <option value="inconclusive">Inconcluant</option>
                </select>
                <button
                  disabled={closeLoading}
                  onClick={closeCase}
                  className="px-4 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-900 dark:text-white text-sm rounded disabled:opacity-40"
                >
                  Clôturer
                </button>
              </div>
            </div>
          )}

          <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-2">
            <p className="text-sm font-medium text-gray-400 dark:text-gray-400 mb-1">Changer la sévérité</p>
            <div className="flex gap-2">
              {severities.map((sv) => (
                <button
                  key={sv}
                  onClick={async () => {
                    const updated = await casesApi.patch(cas.case_id, { severity: sv })
                    setCas(updated)
                  }}
                  className={`text-xs px-2 py-1 rounded ${cas.severity === sv ? 'ring-1 ring-white' : ''}`}
                >
                  <SeverityBadge severity={sv} />
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === 'Preuves' && (
        <div className="space-y-4">
          <form onSubmit={addEvidence} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-3">
            <p className="text-sm font-medium text-gray-700 dark:text-gray-300">Ajouter une preuve</p>
            <div className="flex gap-2">
              <select
                value={evType}
                onChange={(e) => setEvType(e.target.value as EvidenceType)}
                className="bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1.5 text-sm text-gray-900 dark:text-white"
              >
                {EVIDENCE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
              <input
                required
                type="text"
                placeholder="Contenu *"
                value={evContent}
                onChange={(e) => setEvContent(e.target.value)}
                className="flex-1 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1.5 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Description…"
                value={evDesc}
                onChange={(e) => setEvDesc(e.target.value)}
                className="flex-1 bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-2 py-1.5 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
              <button
                type="submit"
                disabled={evLoading}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 dark:bg-blue-700 dark:hover:bg-blue-600 text-gray-900 dark:text-white text-sm rounded disabled:opacity-40"
              >
                Ajouter
              </button>
            </div>
          </form>

          <div className="space-y-2">
            {cas.evidence.length === 0 && <p className="text-gray-400 dark:text-gray-500 text-sm">Aucune preuve</p>}
            {cas.evidence.map((ev) => (
              <div key={ev.evidence_id} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3 text-sm">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs bg-gray-100 dark:bg-gray-800 text-gray-400 dark:text-gray-400 px-1.5 py-0.5 rounded">{ev.type}</span>
                  <span className="text-xs text-gray-400 dark:text-gray-500">
                    par {ev.added_by} · <RelativeTime iso={ev.added_at} />
                  </span>
                </div>
                <p className="mt-1 font-mono text-xs text-gray-700 dark:text-gray-300 break-all">{ev.content}</p>
                {ev.description && <p className="mt-0.5 text-xs text-gray-400 dark:text-gray-400">{ev.description}</p>}
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'Notes' && (
        <div className="space-y-4">
          <form onSubmit={addNote} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4 space-y-3">
            <textarea
              required
              value={noteContent}
              onChange={(e) => setNoteContent(e.target.value)}
              placeholder="Ajouter une note…"
              rows={3}
              className="w-full bg-gray-100 dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 text-sm text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 resize-none"
            />
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={noteLoading}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 dark:bg-blue-700 dark:hover:bg-blue-600 text-gray-900 dark:text-white text-sm rounded disabled:opacity-40"
              >
                Publier
              </button>
            </div>
          </form>
          <div className="space-y-3">
            {cas.notes.length === 0 && <p className="text-gray-400 dark:text-gray-500 text-sm">Aucune note</p>}
            {cas.notes.slice().reverse().map((n) => (
              <div key={n.note_id} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3">
                <div className="flex justify-between text-xs text-gray-400 dark:text-gray-500 mb-1">
                  <span className="text-gray-400 dark:text-gray-400 font-medium">{n.author}</span>
                  <RelativeTime iso={n.created_at} />
                </div>
                <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{n.content}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'Custody' && (
        <div className="space-y-2">
          {cas.custody_log.length === 0 && <p className="text-gray-400 dark:text-gray-500 text-sm">Journal vide</p>}
          {cas.custody_log.map((entry, i) => (
            <div key={i} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-3 text-xs space-y-0.5">
              <div className="flex items-center justify-between">
                <span className="text-gray-900 dark:text-white font-medium">{entry.action}</span>
                <RelativeTime iso={entry.timestamp} />
              </div>
              <p className="text-gray-400 dark:text-gray-400">{entry.operator} — {entry.detail}</p>
              <p className="text-gray-500 dark:text-gray-600 font-mono truncate">{entry.hash}</p>
            </div>
          ))}
        </div>
      )}

      {tab === 'Timeline' && (
        <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 rounded-xl p-4">
          <CaseTimeline entries={timelineEntries} />
        </div>
      )}
    </div>
  )
}
