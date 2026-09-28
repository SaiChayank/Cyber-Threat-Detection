'use client'
import { Activity, ShieldAlert, Timer, ArrowDownLeft, Info } from 'lucide-react'
import { Panel, Skeleton, Eyebrow } from '@/components/ui/panel'
import { Hint } from '@/components/ui/tooltip'
import { formatNumber } from '@/lib/utils'
import type { Telemetry } from '@/schemas/api'

export function Metrics({
  telemetry,
  rate,
  loading,
}: {
  telemetry: Telemetry | null
  rate: number
  loading: boolean
}) {
  const total = telemetry ? Object.values(telemetry.alerts_by_class).reduce((a, b) => a + b, 0) : 0
  const cards = [
    {
      icon: Activity,
      title: 'EVENTS PROCESSED',
      value: telemetry ? formatNumber(telemetry.processed) : '—',
      unit: '',
      note: 'Current replay · incremental inference',
      hint: 'Processing counters reset when a new replay starts.',
    },
    {
      icon: ShieldAlert,
      title: 'ALERTS RECORDED',
      value: telemetry ? formatNumber(total) : '—',
      unit: '',
      note: 'Persistent history · all replay runs',
      hint: 'SQLite retains alerts across replays. The table shows the latest 200.',
    },
    {
      icon: Timer,
      title: 'PROCESSING P95',
      value: telemetry ? telemetry.processing_p95_ms.toFixed(2) : '—',
      unit: 'ms',
      note: 'Feature extraction + inference',
      hint: 'Core processing latency; excludes HTTP, capture parsing and browser delivery.',
    },
    {
      icon: ArrowDownLeft,
      title: 'OBSERVED RATE',
      value: telemetry ? formatNumber(Math.round(rate)) : '—',
      unit: 'events/s',
      note: `${telemetry?.active_sources ?? 0} active sources · ${telemetry?.replay_status ?? 'connecting'}`,
      hint: 'Sampled from processed events every 1.5 seconds. A short replay may finish between samples.',
    },
  ]
  return (
    <section
      aria-label="Live telemetry"
      className="grid grid-cols-1 gap-3 min-[460px]:grid-cols-2 xl:grid-cols-4"
    >
      {cards.map(({ icon: Icon, title, value, unit, note, hint }) => (
        <Panel className="p-5" key={title}>
          <div className="flex items-center justify-between gap-2">
            <Eyebrow className="text-[9px] tracking-[.1em]">{title}</Eyebrow>
            <Hint text={hint}>
              <button
                aria-label={`About ${title.toLowerCase()}`}
                className="flex h-8 w-8 items-center justify-center rounded-lg text-lilac hover:bg-lilac/10"
              >
                <Info size={13} />
              </button>
            </Hint>
          </div>
          {loading ? (
            <Skeleton className="mt-4 h-9 w-28" />
          ) : (
            <div className="mt-3 flex items-baseline gap-2">
              <strong className="font-display text-3xl font-medium tracking-[-.04em]">
                {value}
              </strong>
              <span className="text-[11px] text-muted">{unit}</span>
            </div>
          )}
          <div className="mt-4 flex items-center gap-2 text-[10px] text-muted">
            <Icon size={12} />
            {note}
          </div>
        </Panel>
      ))}
    </section>
  )
}
