'use client'
import { useEffect, useState } from 'react'
import { Gauge, ArrowUpRight } from 'lucide-react'
import { motion, useReducedMotion } from 'motion/react'
import { detectionModules } from '@/constants/threats'
import { Panel, Eyebrow, Skeleton } from '@/components/ui/panel'
import { api } from '@/services/api'
import { formatNumber } from '@/lib/utils'
import type { BenchmarkReport, Dataset } from '@/schemas/api'
import { AnimatedNumber } from '@/components/animated-number'
import { DatasetReadiness } from './dataset-readiness'

export function Coverage({
  counts,
  datasets,
  loading,
}: {
  counts: Record<string, number>
  datasets: Dataset[]
  loading: boolean
}) {
  const reducedMotion = useReducedMotion()
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0)
  return (
    <section id="coverage" className="scroll-mt-24">
      <Panel className="p-5 sm:p-6">
        <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
          <div>
            <Eyebrow>Detection engines</Eyebrow>
            <h2 className="mt-2 font-display text-xl">Threat coverage</h2>
          </div>
          <span className="rounded-full border border-white/10 px-3 py-1.5 text-[9px] text-muted">
            7 detection modules
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2 min-[460px]:grid-cols-2">
          {detectionModules.map(({ id, name, icon: Icon }) => {
            const count = counts[id] || 0
            const share = total > 0 ? count / total : 0
            return (
              <motion.div
                key={id}
                whileHover={reducedMotion ? undefined : { y: -2 }}
                className="rounded-xl border border-white/8 bg-white/2 p-3.5 transition-colors hover:border-white/20"
              >
                <div className="flex items-center gap-2.5">
                  <Icon size={14} className="shrink-0 text-accent" />
                  <span className="min-w-0 flex-1 text-[11px]">{name}</span>
                  {loading ? (
                    <Skeleton className="h-5 w-6" />
                  ) : (
                    <strong className="font-display text-lg font-medium tabular-nums">
                      <AnimatedNumber value={count} />
                    </strong>
                  )}
                </div>
                <div
                  className="mt-3 h-0.5 overflow-hidden rounded-full bg-white/8"
                  aria-hidden="true"
                >
                  <motion.div
                    className="h-full origin-left bg-brand/80"
                    initial={reducedMotion ? false : { scaleX: 0 }}
                    whileInView={{ scaleX: loading ? 0 : share }}
                    viewport={{ once: true }}
                    transition={{ duration: reducedMotion ? 0 : 0.7 }}
                  />
                </div>
              </motion.div>
            )
          })}
        </div>
        <p className="mt-3 text-[10px] leading-5 text-muted">
          Six required categories. Bars show each module’s share of recorded alerts, not accuracy.
          Coverage describes implementation, without implying validated real-world performance.
        </p>
        <DatasetReadiness datasets={datasets} loading={loading} />
      </Panel>
    </section>
  )
}
export function Benchmark() {
  const [report, setReport] = useState<BenchmarkReport | null>(null)
  const [error, setError] = useState(false)
  useEffect(() => {
    const controller = new AbortController()
    api
      .benchmark(controller.signal)
      .then((result) => {
        if (!controller.signal.aborted) setReport(result)
      })
      .catch(() => {
        if (!controller.signal.aborted) setError(true)
      })
    return () => controller.abort()
  }, [])
  return (
    <Panel className="p-5 sm:p-6">
      <div className="flex items-center gap-3">
        <span className="rounded-lg bg-accent/10 p-2 text-accent">
          <Gauge size={19} />
        </span>
        <div>
          <Eyebrow>Saved benchmark · synthetic workload</Eyebrow>
          <h2 className="mt-1 font-display text-lg">Performance, with context.</h2>
        </div>
      </div>
      {error ? (
        <p className="mt-4 text-xs text-muted">
          No saved benchmark is available from this API. Run the documented Python benchmark to
          measure throughput.
        </p>
      ) : !report ? (
        <Skeleton className="mt-5 h-20 w-full" />
      ) : (
        <>
          <div className="mt-5 space-y-4">
            <div className="relative overflow-hidden rounded-xl border border-brand/15 bg-brand/5 p-4">
              <ArrowUpRight
                size={18}
                className="absolute top-4 right-4 text-accent/60"
                aria-hidden="true"
              />
              <p className="text-[10px] text-muted">Measured processing + persistence</p>
              <p className="mt-2 font-display text-3xl text-signal">
                {formatNumber(Math.round(report.metadata_events_per_second))}
                <span className="ml-2 font-sans text-[10px] text-muted">events/s</span>
              </p>
            </div>
            <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-white/8 pb-4">
              <p className="text-[10px] text-muted">Processing + persistence p95</p>
              <p className="font-display text-xl">
                {report.processing_and_persistence_p95_ms.toFixed(2)}
                <span className="ml-2 font-sans text-[10px] text-muted">ms</span>
              </p>
            </div>
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="text-[10px] text-muted">Stated test target</p>
              <p className="font-display text-xl">
                {formatNumber(report.throughput_target)}
                <span className="ml-2 font-sans text-[10px] text-muted">events/s</span>
              </p>
              <p className="w-full text-[10px] text-muted">
                {report.throughput_pass && report.latency_pass
                  ? 'Throughput and latency targets met'
                  : 'One or more targets not met'}
              </p>
            </div>
          </div>
          <p className="mt-5 border-t border-line pt-4 text-[10px] leading-5 text-muted">
            {formatNumber(report.events)} events · {report.elapsed_seconds.toFixed(2)} seconds ·
            Python {report.python}
            <br />
            {report.workload}. {report.scope}. This saved result does not measure browser delivery
            or real deployment capacity.
          </p>
        </>
      )}
    </Panel>
  )
}
