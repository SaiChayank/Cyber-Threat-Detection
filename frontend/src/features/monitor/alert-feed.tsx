'use client'
import { useReducedMotion } from '@/hooks/use-reduced-motion'
import { useMemo, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { ArrowRight, Download, Radar, ChevronLeft, ChevronRight, Pause, Play } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Panel, Eyebrow, Skeleton } from '@/components/ui/panel'
import { Hint } from '@/components/ui/tooltip'
import { threatName } from '@/constants/threats'
import { formatTime } from '@/lib/utils'
import type { AlertRecord } from '@/schemas/api'
import { Severity } from './severity'
import { AlertDetail } from './alert-detail'
import { AnimatedNumber } from '@/components/animated-number'
import { AlertFilters } from './alert-filters'

export function AlertFeed({
  records,
  loading,
  lateEvents,
  live,
  unavailable = false,
}: {
  records: AlertRecord[]
  loading: boolean
  lateEvents: number
  live: boolean
  unavailable?: boolean
}) {
  const [threat, setThreat] = useState('')
  const [severity, setSeverity] = useState('')
  const [search, setSearch] = useState('')
  const [engine, setEngine] = useState('')
  const [snapshot, setSnapshot] = useState<AlertRecord[] | null>(null)
  const [selected, setSelected] = useState<AlertRecord | null>(null)
  const [page, setPage] = useState(0)
  const [exported, setExported] = useState<number | null>(null)
  const reducedMotion = useReducedMotion()
  const displayed = snapshot ?? records
  const boundary = snapshot?.reduce((max, alert) => Math.max(max, alert.sequence), 0) ?? 0
  const pending = snapshot ? records.filter((alert) => alert.sequence > boundary).length : 0
  const engines = [
    ...new Set([...displayed.map((alert) => alert.detection_source), ...(engine ? [engine] : [])]),
  ].sort()
  const filtered = useMemo(
    () =>
      displayed.filter(
        (alert) =>
          (!threat || alert.threat_class === threat) &&
          (!severity || alert.severity === severity) &&
          (!engine || alert.detection_source === engine) &&
          (!search ||
            `${alert.src_ip} ${alert.dst_ip} ${alert.flow_id} ${alert.alert_id} ${alert.supporting_evidence} ${threatName(alert.threat_class)}`
              .toLowerCase()
              .includes(search.toLowerCase())),
      ),
    [displayed, threat, severity, engine, search],
  )
  const pages = Math.max(1, Math.ceil(filtered.length / 10))
  const current = Math.min(page, pages - 1)
  const rows = filtered.slice(current * 10, (current + 1) * 10)
  const filtering = !!(threat || severity || search || engine)
  function resetPage() {
    setPage(0)
    setExported(null)
  }
  function resetFilters() {
    setSearch('')
    setThreat('')
    setSeverity('')
    setEngine('')
    resetPage()
  }
  function toggleSnapshot() {
    setSnapshot(snapshot ? null : records.slice(0, 200))
    resetPage()
  }
  function exportJSON() {
    const blob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `univect-alerts-${Date.now()}.json`
    link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    setExported(filtered.length)
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
            <div className="flex flex-wrap items-center gap-2 sm:gap-4">
              <span className="hidden border-r border-white/10 pr-4 text-right sm:block">
                <AnimatedNumber
                  value={displayed.length}
                  className="font-display text-2xl tabular-nums"
                />
                <span className="mt-1 block text-[9px] text-muted">loaded signals</span>
              </span>
              <Hint text="Hold the visible queue for investigation. Ingest and metrics continue; resume shows the latest 200 loaded records.">
                <Button
                  onClick={toggleSnapshot}
                  disabled={loading || (!snapshot && !records.length)}
                  aria-pressed={!!snapshot}
                  className="text-xs"
                >
                  {snapshot ? <Play size={14} /> : <Pause size={14} />}
                  {snapshot ? 'Resume queue' : 'Hold queue'}
                </Button>
              </Hint>
              <Hint
                text={
                  snapshot
                    ? 'Exports all matching records from the held snapshot, across all table pages.'
                    : 'Exports all matches within the latest 200 loaded records, across all table pages.'
                }
              >
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
          </div>
          <AlertFilters
            search={search}
            threat={threat}
            severity={severity}
            engine={engine}
            engines={engines}
            onSearch={(value) => {
              setSearch(value)
              resetPage()
            }}
            onThreat={(value) => {
              setThreat(value)
              resetPage()
            }}
            onSeverity={(value) => {
              setSeverity(value)
              resetPage()
            }}
            onEngine={(value) => {
              setEngine(value)
              resetPage()
            }}
            onReset={resetFilters}
          />
          <AnimatePresence initial={false}>
            {snapshot && (
              <motion.div
                key="held-queue"
                initial={reducedMotion ? false : { opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: reducedMotion ? 'auto' : 0 }}
                transition={{ duration: reducedMotion ? 0 : 0.24 }}
                className="overflow-hidden"
              >
                <p
                  role="status"
                  className="rounded-xl border border-white/10 bg-white/3 px-4 py-3 text-[11px] leading-5 text-muted"
                >
                  <span className="font-medium text-white">Queue held.</span> {pending} newer loaded
                  alerts. Ingest and metrics continue. Resume shows the latest 200 records.
                </p>
              </motion.div>
            )}
          </AnimatePresence>
          {exported !== null && (
            <p role="status" className="text-[11px] text-signal">
              JSON export generated with {exported} matching records.
            </p>
          )}
        </div>
        <div
          className="overflow-x-auto"
          role="region"
          aria-label="Alert results"
          tabIndex={loading || rows.length ? 0 : undefined}
        >
          {loading || rows.length ? (
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
              <motion.tbody
                key={`${current}-${threat}-${severity}-${engine}`}
                initial={reducedMotion ? false : { opacity: 0.55 }}
                animate={{ opacity: 1 }}
                transition={{ duration: reducedMotion ? 0 : 0.25 }}
              >
                {loading
                  ? Array.from({ length: 5 }, (_, index) => (
                      <tr key={index} className="border-b border-line/70">
                        {Array.from({ length: 7 }, (_, cell) => (
                          <td className="p-4" key={cell}>
                            <Skeleton className="h-4 w-20" />
                          </td>
                        ))}
                      </tr>
                    ))
                  : rows.length
                    ? rows.map((alert) => (
                        <motion.tr
                          key={alert.sequence}
                          initial={reducedMotion ? false : { opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ duration: reducedMotion ? 0 : 0.28 }}
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
                              <span
                                tabIndex={0}
                                className="inline-block min-w-11 text-xs text-accent"
                              >
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
                        </motion.tr>
                      ))
                    : null}
              </motion.tbody>
            </table>
          ) : (
            <div className="flex min-h-60 flex-col items-center justify-center gap-3 border-y border-line p-8 text-center">
              <Radar size={32} strokeWidth={1.2} className="text-accent" />
              <h3 className="font-display text-lg">
                {filtering
                  ? 'No matching signals.'
                  : unavailable
                    ? 'Waiting for the local API.'
                    : 'Ready to observe.'}
              </h3>
              <p className="text-xs text-muted">
                {filtering
                  ? 'Try a broader search or remove a filter.'
                  : unavailable
                    ? 'Reconnect the API to load saved alerts and enable replay.'
                    : 'Start a traffic replay to see detections and supporting evidence.'}
              </p>
            </div>
          )}
        </div>
        {!!rows.length && (
          <p className="px-5 pt-3 text-[10px] text-muted lg:hidden">
            Scroll the table horizontally to view every column and inspect an alert.
          </p>
        )}
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 text-[9px] text-muted sm:px-6">
          <span>
            {filtered.length} matching / {displayed.length} loaded ·{' '}
            {snapshot ? 'Held snapshot' : 'Latest 200'} · Newest first
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
