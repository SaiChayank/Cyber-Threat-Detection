'use client'
import { ArrowRight, Network, Activity, CornerDownLeft, Layers } from 'lucide-react'
import { Panel, Eyebrow, Skeleton } from '@/components/ui/panel'
import { BrandMark } from '@/components/brand'
import { AnimatedNumber } from '@/components/animated-number'
import type { Telemetry } from '@/schemas/api'

export function ObservationContext({
  telemetry,
  loading,
}: {
  telemetry: Telemetry | null
  loading: boolean
}) {
  const running = telemetry?.replay_status === 'running'
  const counters = [
    { label: 'Active sources', value: telemetry?.active_sources, icon: Activity },
    { label: 'Late events dropped', value: telemetry?.late_events, icon: CornerDownLeft },
    { label: 'State evictions', value: telemetry?.state_evictions, icon: Layers },
  ]
  return (
    <Panel className="flex h-full flex-col p-5 sm:p-6">
      <div className="flex items-center justify-between gap-2">
        <Eyebrow>Collection boundary</Eyebrow>
        <span className="rounded-full border border-white/10 px-2.5 py-1 text-[8px] tracking-[.1em] text-muted">
          LAB PROTOTYPE
        </span>
      </div>
      <h2 className="mt-2 font-display text-xl tracking-[-.03em]">Passive by design.</h2>
      <div className="my-5 flex items-center gap-3 rounded-xl border border-white/8 bg-ink/40 p-3">
        <Network size={19} className="shrink-0 text-muted" />
        <div className="min-w-0 flex-1">
          <p className="text-[11px]">Mirror feed</p>
          <p className="mt-1 text-[9px] text-muted">Read-only input</p>
        </div>
        <div
          className={`flow-link relative h-px w-9 shrink-0 bg-white/15 ${running ? 'flow-link-active' : ''}`}
          aria-hidden="true"
        >
          <ArrowRight size={12} className="absolute -top-1.5 -right-0.5 text-accent" />
        </div>
        <BrandMark className="h-6 w-6 shrink-0" />
        <span className="text-[10px]">Enclave</span>
      </div>
      <dl className="space-y-3">
        {counters.map(({ label, value, icon: Icon }) => (
          <div key={label} className="flex items-center justify-between gap-3 text-[10px]">
            <dt className="flex items-center gap-2 text-muted">
              <Icon size={12} />
              {label}
            </dt>
            <dd className="tabular-nums text-white">
              {loading ? (
                <Skeleton className="h-3 w-6" />
              ) : value === undefined ? (
                '—'
              ) : (
                <AnimatedNumber value={value} />
              )}
            </dd>
          </div>
        ))}
      </dl>
      <p className="mt-5 border-t border-white/8 pt-4 text-[10px] leading-5 text-muted">
        Metadata only. No payload decryption, path to the source or network actions.
      </p>
    </Panel>
  )
}
