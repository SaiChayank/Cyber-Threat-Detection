'use client'
import { useEffect, useState } from 'react'
import { Database, CheckCircle2, CircleAlert, Gauge } from 'lucide-react'
import { detectionModules } from '@/constants/threats'
import { Panel, Eyebrow, Skeleton } from '@/components/ui/panel'
import { api } from '@/services/api'
import { formatNumber } from '@/lib/utils'
import type { BenchmarkReport, Dataset } from '@/schemas/api'

export function Coverage({
  counts,
  datasets,
  loading,
}: {
  counts: Record<string, number>
  datasets: Dataset[]
  loading: boolean
}) {
  return (
    <section id="coverage" className="scroll-mt-24">
      <div className="mb-4 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
        <div>
          <Eyebrow>Detection engines</Eyebrow>
          <h2 className="mt-2 font-display text-xl">Threat coverage</h2>
        </div>
        <p className="text-[10px] text-muted">Six required categories · Seven detection modules</p>
      </div>
      <div className="grid grid-cols-1 gap-2 min-[460px]:grid-cols-2 xl:grid-cols-4">
        {detectionModules.map(({ id, name, icon: Icon }) => (
          <Panel key={id} className="flex items-center gap-3 px-4 py-4">
            <span className="rounded-lg bg-lilac/10 p-2 text-lilac">
              <Icon size={15} />
            </span>
            <span className="flex-1 text-xs">{name}</span>
            {loading ? (
              <Skeleton className="h-5 w-6" />
            ) : (
              <strong className="font-display text-lg font-medium">{counts[id] || 0}</strong>
            )}
          </Panel>
        ))}
      </div>
      <p className="mt-3 text-[10px] leading-5 text-muted">
        Counts reflect recorded alerts. Coverage describes implemented modules, without implying
        validated real-world accuracy.
      </p>
      <details className="mt-5 rounded-xl border border-line bg-panel p-5">
        <summary className="cursor-pointer text-xs font-medium text-lilac">
          <span className="inline-flex items-center gap-2">
            <Database size={14} />
            Public-source dataset readiness
          </span>
        </summary>
        <div className="mt-4 space-y-3">
          {loading ? (
            <Skeleton className="h-20 w-full" />
          ) : datasets.length ? (
            datasets.map((dataset) => (
              <div
                key={dataset.id}
                className="flex items-start gap-3 border-t border-line pt-3 text-[11px]"
              >
                <span className="mt-0.5 text-lime">
                  {dataset.ready ? (
                    <CheckCircle2 size={13} />
                  ) : (
                    <CircleAlert size={13} className="text-amber-300" />
                  )}
                </span>
                <div>
                  <p>{dataset.name}</p>
                  <p className="mt-1.5 text-[10px] leading-5 text-muted">
                    {dataset.ready
                      ? `Downloaded · Up to ${formatNumber(dataset.event_limit)} events per replay`
                      : 'Unavailable locally · preparation required'}
                    <br />
                    {dataset.model}
                  </p>
                </div>
              </div>
            ))
          ) : (
            <p className="text-xs text-muted">Dataset status will appear when the API connects.</p>
          )}
          <p className="text-[10px] leading-5 text-muted">
            UMUDGA provides real domain strings with simulated DNS timing. CIC DNS presets replay
            captured metadata. IoT-23 is excluded because authorization was not provided.
          </p>
        </div>
      </details>
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
        <span className="rounded-lg bg-lilac/10 p-2 text-lilac">
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
          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <div>
              <p className="text-[10px] text-muted">Measured processing + persistence</p>
              <p className="mt-2 font-display text-2xl text-lime">
                {formatNumber(Math.round(report.metadata_events_per_second))}
                <span className="ml-2 font-sans text-[10px] text-muted">events/s</span>
              </p>
            </div>
            <div>
              <p className="text-[10px] text-muted">Processing + persistence p95</p>
              <p className="mt-2 font-display text-2xl">
                {report.processing_and_persistence_p95_ms.toFixed(2)}
                <span className="ml-2 font-sans text-[10px] text-muted">ms</span>
              </p>
            </div>
            <div>
              <p className="text-[10px] text-muted">Stated test target</p>
              <p className="mt-2 font-display text-2xl">
                {formatNumber(report.throughput_target)}
                <span className="ml-2 font-sans text-[10px] text-muted">events/s</span>
              </p>
              <p className="mt-1 text-[10px] text-muted">
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
