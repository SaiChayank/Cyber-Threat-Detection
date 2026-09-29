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
import { useReducedMotion } from 'motion/react'
import { Activity } from 'lucide-react'
import { Panel, Eyebrow, Skeleton } from '@/components/ui/panel'
import { AnimatedNumber } from '@/components/animated-number'
import type { RateSample } from '@/schemas/api'

export function TrafficChart({
  samples,
  loading,
  rate,
  state,
}: {
  samples: RateSample[]
  loading: boolean
  rate: number
  state: string
}) {
  const reducedMotion = useReducedMotion()
  return (
    <Panel className="flex h-full min-w-0 flex-col p-5 sm:p-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <Eyebrow className="flex items-center gap-2">
            <Activity size={12} className="text-accent" />
            Ingest telemetry
          </Eyebrow>
          <h2 className="mt-2 font-display text-xl tracking-[-.03em]">Observed event rate</h2>
          <p className="mt-2 text-[11px] text-muted">24 recent samples · local UTC clock</p>
        </div>
        <div className="text-right">
          <AnimatedNumber
            value={Math.round(rate)}
            className="font-display text-2xl font-medium tabular-nums text-signal"
          />
          <span className="mt-1 block text-[9px] text-muted">events / sec</span>
        </div>
      </div>
      <div className="mt-6 h-44 min-w-0 sm:h-48" aria-label="Observed event rate chart">
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
                  <stop offset="0%" stopColor="#c9323c" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#c9323c" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} stroke="#303232" strokeDasharray="3 5" />
              <XAxis
                dataKey="time"
                tick={{ fill: '#a8abab', fontSize: 9 }}
                axisLine={false}
                tickLine={false}
                minTickGap={60}
              />
              <YAxis
                tick={{ fill: '#a8abab', fontSize: 9 }}
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
                stroke="#f07878"
                strokeWidth={2}
                fill="url(#rate-fill)"
                isAnimationActive={!reducedMotion}
                animationDuration={500}
                animationEasing="ease-out"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-white/8 pt-4 text-[9px] leading-5 text-muted">
        <span>
          Replay state: <span className="text-white capitalize">{state}</span>
        </span>
        <span>Packet records and flow summaries are different units.</span>
      </div>
    </Panel>
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
    <div className="rounded-lg border border-line bg-[#202222] p-3 text-xs">
      <p className="text-muted">{label} UTC</p>
      <p className="mt-1 text-signal">{payload[0].value} events / sec</p>
    </div>
  )
}
