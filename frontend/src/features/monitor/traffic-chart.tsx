'use client'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { LockKeyhole, Network, ArrowRight, ShieldCheck } from 'lucide-react'
import { Panel, Eyebrow, Skeleton } from '@/components/ui/panel'
import type { RateSample } from '@/schemas/api'
import { formatNumber } from '@/lib/utils'

export function TrafficChart({
  samples,
  loading,
  rate,
}: {
  samples: RateSample[]
  loading: boolean
  rate: number
}) {
  return (
    <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
      <Panel className="min-w-0 p-5 sm:p-6">
        <div className="flex items-start justify-between gap-4">
          <div>
            <Eyebrow>Ingest telemetry</Eyebrow>
            <h2 className="mt-2 font-display text-xl tracking-[-.03em]">Observed event rate</h2>
            <p className="mt-2 text-[11px] text-muted">24 recent samples · local UTC clock</p>
          </div>
          <div className="text-right">
            <strong className="font-display text-2xl font-medium text-lime">
              {formatNumber(Math.round(rate))}
            </strong>
            <span className="mt-1 block text-[9px] text-muted">events / sec</span>
          </div>
        </div>
        <div className="mt-7 h-40 min-w-0" aria-label="Observed event rate chart">
          {loading ? (
            <Skeleton className="h-full w-full" />
          ) : samples.length < 2 ? (
            <div className="flex h-full items-center justify-center rounded-xl border border-dashed border-line text-xs text-muted">
              Collecting telemetry samples…
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%" minWidth={1} minHeight={1}>
              <AreaChart data={samples} margin={{ top: 6, right: 5, bottom: 0, left: -15 }}>
                <defs>
                  <linearGradient id="rate-fill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#d5f5bd" stopOpacity={0.22} />
                    <stop offset="100%" stopColor="#d5f5bd" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid vertical={false} stroke="#292332" strokeDasharray="3 5" />
                <XAxis
                  dataKey="time"
                  tick={{ fill: '#a39aad', fontSize: 9 }}
                  axisLine={false}
                  tickLine={false}
                  minTickGap={60}
                />
                <YAxis
                  tick={{ fill: '#a39aad', fontSize: 9 }}
                  axisLine={false}
                  tickLine={false}
                  width={45}
                  allowDecimals={false}
                />
                <Tooltip content={<RateTooltip />} />
                <Area
                  name="Events/s"
                  type="linear"
                  dataKey="rate"
                  stroke="#d5f5bd"
                  strokeWidth={2}
                  fill="url(#rate-fill)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
        <p className="mt-3 text-[9px] leading-5 text-muted">
          Replay rate reflects event processing. Captured packet records and flow summaries are
          different units.
        </p>
      </Panel>
      <Boundary />
    </div>
  )
}
function RateTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean
  payload?: readonly { value?: number | string; dataKey?: string | number }[]
  label?: string | number
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-line bg-[#201a2d] p-3 text-xs">
      <p className="text-muted">{label} UTC</p>
      <p className="mt-1 text-lime">{payload[0].value} events / sec</p>
    </div>
  )
}
function Boundary() {
  return (
    <Panel className="flex flex-col p-6">
      <Eyebrow>Collection boundary</Eyebrow>
      <h2 className="mt-2 font-display text-xl tracking-[-.03em]">One-way by design</h2>
      <p className="mt-3 text-xs leading-6 text-muted">
        The sensor receives mirrored traffic and emits intelligence to this analyst interface.
      </p>
      <div className="my-7 flex items-center justify-between gap-2">
        <div className="flex flex-col items-center gap-2">
          <span className="rounded-xl border border-line bg-ink p-3 text-muted">
            <Network size={20} />
          </span>
          <span className="text-[10px]">Mirror feed</span>
          <span className="text-[9px] text-muted">Read only</span>
        </div>
        <ArrowRight size={20} className="text-lilac/60" />
        <div className="flex flex-col items-center gap-2">
          <span className="rounded-xl border border-lilac/25 bg-lilac/10 p-3 text-lilac">
            <ShieldCheck size={20} />
          </span>
          <span className="text-[10px]">Analytics enclave</span>
          <span className="text-[9px] text-muted">Metadata only</span>
        </div>
      </div>
      <div className="mt-auto flex flex-wrap justify-between gap-2 border-t border-line pt-4 text-[9px] text-muted">
        <span className="flex items-center gap-1.5">
          <LockKeyhole size={11} />
          No path to source
        </span>
        <span>No payload decryption</span>
      </div>
    </Panel>
  )
}
