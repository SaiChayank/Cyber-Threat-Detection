'use client'
import { useMemo, useState } from 'react'
import { ArrowRight, Download, Search, Radar, ChevronLeft, ChevronRight, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Panel, Eyebrow, Skeleton } from '@/components/ui/panel'
import { Hint } from '@/components/ui/tooltip'
import { detectionModules, threatName } from '@/constants/threats'
import { formatTime } from '@/lib/utils'
import type { AlertRecord } from '@/schemas/api'
import { Severity } from './severity'
import { AlertDetail } from './alert-detail'

export function AlertFeed({
  records,
  loading,
  lateEvents,
  live,
}: {
  records: AlertRecord[]
  loading: boolean
  lateEvents: number
  live: boolean
}) {
  const [threat, setThreat] = useState('')
  const [severity, setSeverity] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<AlertRecord | null>(null)
  const [page, setPage] = useState(0)
  const [exported, setExported] = useState(false)
  const filtered = useMemo(
    () =>
      records.filter(
        (alert) =>
          (!threat || alert.threat_class === threat) &&
          (!severity || alert.severity === severity) &&
          (!search ||
            `${alert.src_ip} ${alert.dst_ip} ${alert.flow_id} ${alert.alert_id} ${alert.supporting_evidence} ${threatName(alert.threat_class)}`
              .toLowerCase()
              .includes(search.toLowerCase())),
      ),
    [records, threat, severity, search],
  )
  const pages = Math.max(1, Math.ceil(filtered.length / 10))
  const current = Math.min(page, pages - 1)
  const rows = filtered.slice(current * 10, (current + 1) * 10)
  const filtering = !!(threat || severity || search)
  function exportJSON() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `univect-alerts-${Date.now()}.json`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    setExported(true)
  }
  return (
    <section id="alerts" className="scroll-mt-24">
      <Panel className="overflow-hidden">
        <div className="flex flex-col justify-between gap-5 p-5 sm:p-6">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <Eyebrow>Investigation queue</Eyebrow>
              <h2 className="mt-2 flex items-center gap-3 font-display text-xl">
                Alert stream{' '}
                <span
                  className={`rounded-full border px-2 py-1 font-sans text-[8px] tracking-[.1em] ${live ? 'border-signal/20 bg-signal/5 text-signal' : 'border-line text-muted'}`}
                >
                  {live ? 'LIVE' : 'RECONNECTING'}
                </span>
              </h2>
              <p className="mt-2 text-[11px] text-muted">
                Inspect a detection to follow its observed evidence.
              </p>
            </div>
            <Hint text="Exports all matches within the latest 200 loaded records, across all table pages.">
              <Button
                onClick={exportJSON}
                disabled={!filtered.length || loading}
                className="text-xs"
              >
                <Download size={14} />
                Export JSON
              </Button>
            </Hint>
          </div>
          <div className="grid gap-2 sm:grid-cols-[1fr_170px_145px]">
            <div className="relative">
              <Search size={14} className="absolute top-3.5 left-3 text-muted" />
              <input
                type="search"
                aria-label="Search alerts"
                placeholder="Search IP, flow ID or evidence…"
                value={search}
                onChange={(event) => {
                  setSearch(event.target.value)
                  setPage(0)
                  setExported(false)
                }}
                className="min-h-11 w-full rounded-xl border border-line bg-ink pr-3 pl-9 text-xs placeholder:text-muted/70"
              />
            </div>
            <select
              aria-label="Filter threat class"
              value={threat}
              onChange={(event) => {
                setThreat(event.target.value)
                setPage(0)
                setExported(false)
              }}
              className="min-h-11 rounded-xl border border-line bg-ink px-3 text-xs"
            >
              <option value="">All threats</option>
              {detectionModules.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
            <select
              aria-label="Filter severity"
              value={severity}
              onChange={(event) => {
                setSeverity(event.target.value)
                setPage(0)
                setExported(false)
              }}
              className="min-h-11 rounded-xl border border-line bg-ink px-3 text-xs"
            >
              <option value="">All severities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((item) => (
                <option key={item}>{item}</option>
              ))}
            </select>
          </div>
          {exported && (
            <p role="status" className="text-[11px] text-signal">
              JSON export generated with {filtered.length} matching records.
            </p>
          )}
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[770px] border-collapse text-left">
            <caption className="sr-only">
              Newest recorded detections with observed event time, threat, connection, severity,
              confidence and detection engine. Use Inspect to view evidence.
            </caption>
            <thead className="border-y border-line bg-ink/50 text-[9px] tracking-[.08em] text-muted">
              <tr>
                {[
                  'OBSERVED TIME (UTC)',
                  'THREAT',
                  'SOURCE → DESTINATION',
                  'SEVERITY',
                  'CONFIDENCE',
                  'ENGINE',
                  '',
                ].map((heading, index) => (
                  <th scope="col" className="px-4 py-3 font-medium first:pl-6" key={index}>
                    {heading || <span className="sr-only">Investigation</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                Array.from({ length: 5 }, (_, index) => (
                  <tr key={index} className="border-b border-line/70">
                    {Array.from({ length: 7 }, (_, cell) => (
                      <td className="p-4" key={cell}>
                        <Skeleton className="h-4 w-20" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : rows.length ? (
                rows.map((alert) => (
                  <tr
                    key={alert.sequence}
                    className="border-b border-white/6 text-xs transition odd:bg-white/[.015] hover:bg-brand/5"
                  >
                    <td className="py-4 pr-3 pl-6 font-mono text-[10px] text-muted">
                      {formatTime(alert.timestamp)}
                      <span className="mt-1 block text-[9px] text-muted/70">
                        {new Date(alert.timestamp).toISOString().slice(0, 10)}
                      </span>
                    </td>
                    <td className="px-4 py-4 font-medium whitespace-nowrap">
                      {threatName(alert.threat_class)}
                    </td>
                    <td className="px-4 py-4 font-mono text-[10px]">
                      <span>{alert.src_ip}</span>
                      <span className="mt-1 flex items-center gap-1.5 text-muted">
                        <ArrowRight size={10} />
                        {alert.dst_ip}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <Severity severity={alert.severity} />
                    </td>
                    <td className="px-4 py-4">
                      <Hint
                        text={String(
                          alert.raw_evidence_metrics.confidence_kind ??
                            'Uncalibrated detector score',
                        )}
                      >
                        <span tabIndex={0} className="inline-block min-w-11 text-xs text-accent">
                          {(alert.confidence_score * 100).toFixed(1)}%
                        </span>
                      </Hint>
                    </td>
                    <td className="px-4 py-4">
                      <span className="rounded border border-line px-2 py-1 text-[9px] text-muted">
                        {alert.detection_source}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <Button
                        variant="ghost"
                        className="min-h-9 px-3 text-[10px] text-accent"
                        data-alert={alert.sequence}
                        aria-label={`Inspect ${threatName(alert.threat_class)} alert ${alert.sequence}`}
                        onClick={() => setSelected(alert)}
                      >
                        Inspect <ArrowRight size={12} />
                      </Button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7}>
                    <div className="flex min-h-60 flex-col items-center justify-center gap-3 p-8 text-center">
                      <Radar size={32} strokeWidth={1.2} className="text-accent" />
                      <h3 className="font-display text-lg">
                        {filtering ? 'No matching signals.' : 'Ready to observe.'}
                      </h3>
                      <p className="text-xs text-muted">
                        {filtering
                          ? 'Try a broader search or remove a filter.'
                          : 'Start a traffic replay to see detections and supporting evidence.'}
                      </p>
                      {filtering && (
                        <Button
                          variant="ghost"
                          onClick={() => {
                            setSearch('')
                            setThreat('')
                            setSeverity('')
                            setPage(0)
                          }}
                        >
                          <X size={14} />
                          Clear filters
                        </Button>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 text-[9px] text-muted sm:px-6">
          <span>
            {filtered.length} matching / {records.length} loaded · Latest 200 · Newest first
          </span>
          <div className="flex items-center gap-2">
            <span>{lateEvents} late events dropped</span>
            <Button
              variant="ghost"
              className="h-9 min-h-9 w-9 p-0"
              aria-label="Previous alert page"
              disabled={current === 0}
              onClick={() => setPage(current - 1)}
            >
              <ChevronLeft size={15} />
            </Button>
            <span>
              {current + 1} / {pages}
            </span>
            <Button
              variant="ghost"
              className="h-9 min-h-9 w-9 p-0"
              aria-label="Next alert page"
              disabled={current >= pages - 1}
              onClick={() => setPage(current + 1)}
            >
              <ChevronRight size={15} />
            </Button>
          </div>
        </div>
      </Panel>
      <AlertDetail alert={selected} onClose={() => setSelected(null)} />
    </section>
  )
}
