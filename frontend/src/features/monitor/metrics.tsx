'use client'
import { motion, useReducedMotion } from 'motion/react'
import { Activity, ShieldAlert, Timer, ArrowDownLeft, Info } from 'lucide-react'
import { Panel, Skeleton, Eyebrow } from '@/components/ui/panel'
import { Hint } from '@/components/ui/tooltip'
import { AnimatedNumber } from '@/components/animated-number'
import { easeOut } from '@/lib/motion'
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
  const reducedMotion = useReducedMotion()
  const total = telemetry ? Object.values(telemetry.alerts_by_class).reduce((a, b) => a + b, 0) : 0
  const cards = [
    {
      icon: Activity,
      title: 'EVENTS PROCESSED',
      value: telemetry?.processed,
      decimals: undefined,
      unit: '',
      note: 'Current replay · incremental inference',
      hint: 'Processing counters reset when a new replay starts.',
    },
    {
      icon: ShieldAlert,
      title: 'ALERTS RECORDED',
      value: telemetry ? total : undefined,
      decimals: undefined,
      unit: '',
      note: 'Persistent history · all replay runs',
      hint: 'SQLite retains alerts across replays. The table shows the latest 200.',
    },
    {
      icon: Timer,
      title: 'PROCESSING P95',
      value: telemetry?.processing_p95_ms,
      decimals: 2,
      unit: 'ms',
      note: 'Feature extraction + inference',
      hint: 'Core processing latency; excludes HTTP, capture parsing and browser delivery.',
    },
    {
      icon: ArrowDownLeft,
      title: 'OBSERVED RATE',
      value: telemetry ? Math.round(rate) : undefined,
      decimals: undefined,
      unit: 'events/s',
      note: `${telemetry?.active_sources ?? 0} active sources · ${telemetry?.replay_status ?? 'connecting'}`,
      hint: 'Sampled from processed events every 1.5 seconds. A short replay may finish between samples.',
    },
  ]
  return (
    <section
      aria-label="Live telemetry"
      className="grid grid-cols-1 gap-3 min-[460px]:grid-cols-2 lg:grid-cols-4"
    >
      {cards.map(({ icon: Icon, title, value, decimals, unit, note, hint }, index) => (
        <motion.div
          key={title}
          initial={reducedMotion ? false : { opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, amount: 0.1 }}
          whileHover={reducedMotion ? undefined : { y: -3 }}
          transition={{
            duration: reducedMotion ? 0 : 0.6,
            delay: reducedMotion ? 0 : index * 0.045,
            ease: easeOut,
          }}
        >
          <Panel className="relative h-full overflow-hidden p-5 sm:p-6">
            <div aria-hidden="true" className="absolute top-0 left-6 h-px w-12 bg-brand/60" />
            <div className="flex items-center justify-between gap-2">
              <Eyebrow className="text-[9px] tracking-[.1em]">{title}</Eyebrow>
              <Hint text={hint}>
                <button
                  aria-label={`About ${title.toLowerCase()}`}
                  className="flex h-8 w-8 items-center justify-center rounded-lg text-accent hover:bg-accent/10"
                >
                  <Info size={13} />
                </button>
              </Hint>
            </div>
            {loading ? (
              <Skeleton className="mt-4 h-9 w-28" />
            ) : (
              <div className="mt-3 flex items-baseline gap-2">
                <strong className="font-display text-4xl font-medium tracking-[-.04em] tabular-nums">
                  {value === undefined ? '—' : <AnimatedNumber value={value} decimals={decimals} />}
                </strong>
                <span className="text-[11px] text-muted">{unit}</span>
              </div>
            )}
            <div className="mt-4 flex items-center gap-2 text-[10px] text-muted">
              <Icon size={12} />
              {note}
            </div>
          </Panel>
        </motion.div>
      ))}
    </section>
  )
}
