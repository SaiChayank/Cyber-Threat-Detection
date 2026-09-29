'use client'
import { motion } from 'motion/react'
import { MoveRight, CircleAlert, RefreshCw, Radio } from 'lucide-react'
import { useMonitor } from '@/hooks/use-monitor'
import { Button } from '@/components/ui/button'
import { Eyebrow } from '@/components/ui/panel'
import { SiteNav } from '@/components/site-nav'
import { SiteFooter } from '@/components/site-footer'
import { Reveal } from '@/components/reveal'
import { cn } from '@/lib/utils'
import { Metrics } from './metrics'
import { TrafficChart } from './traffic-chart'
import { ObservationContext } from './observation-context'
import { ReplayControls } from './replay-controls'
import { Coverage, Benchmark } from './coverage'
import { AlertFeed } from './alert-feed'

export function Monitor() {
  const { alerts, telemetry, datasets, samples, connection, error, loading, refresh } = useMonitor()
  const rate = samples.at(-1)?.rate ?? 0
  return (
    <div className="relative isolate min-h-screen">
      <div className="product-background -z-10" aria-hidden="true" />
      <SiteNav monitor />
      <motion.main
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.45 }}
        id="main-content"
      >
        <div className="mx-auto max-w-[1440px] space-y-6 px-5 pt-8 pb-16 sm:px-8 lg:px-12">
          <header
            id="overview"
            className="relative flex flex-col justify-between gap-5 border-b border-white/8 pb-6 sm:flex-row sm:items-center"
          >
            <div>
              <Eyebrow className="flex items-center gap-2 text-accent">
                <MoveRight size={14} /> Observation workspace
              </Eyebrow>
              <h1 className="mt-3 font-display text-[clamp(32px,4vw,46px)] leading-[1.1] font-medium tracking-[-.05em]">
                Your network, in view<span className="text-accent">.</span>
              </h1>
              <p className="mt-3 max-w-xl text-xs leading-6 text-muted">
                Set the stream. Follow the activity. Investigate the evidence.
              </p>
            </div>
            <div
              role="status"
              className="flex w-fit shrink-0 items-center gap-2.5 rounded-full border border-white/10 bg-panel/60 px-4 py-3 text-[10px] backdrop-blur-md"
            >
              <span className="relative flex h-5 w-5 items-center justify-center">
                {connection === 'live' && (
                  <span
                    aria-hidden="true"
                    className="connection-ring absolute inset-0 rounded-full border border-white/25"
                  />
                )}
                <Radio
                  size={14}
                  className={cn(connection === 'live' ? 'text-signal' : 'text-accent')}
                />
              </span>
              {connection === 'live'
                ? 'Stream connected'
                : connection === 'connecting'
                  ? 'Connecting'
                  : 'Reconnecting'}
              <span className="mx-1 text-line">/</span>
              <span className="text-muted">LOCAL ENCLAVE</span>
            </div>
          </header>
          {error && (
            <div
              role="alert"
              className="flex flex-wrap items-center gap-3 rounded-xl border border-brand/25 bg-brand/5 p-4 text-xs text-accent"
            >
              <CircleAlert size={16} />
              <p className="min-w-0 flex-1 leading-5">{error}</p>
              <Button variant="ghost" className="text-current" onClick={() => void refresh()}>
                <RefreshCw size={13} /> Retry connection
              </Button>
            </div>
          )}
          {telemetry?.replay_error && (
            <div
              role="alert"
              className="rounded-xl border border-brand/25 bg-brand/5 p-4 text-xs leading-6 text-accent"
            >
              Replay failed: {telemetry.replay_error}
            </div>
          )}
          <Reveal delay={0.04}>
            <ReplayControls
              datasets={datasets}
              state={telemetry?.replay_status ?? 'idle'}
              refresh={refresh}
              connected={!!telemetry && !error}
            />
          </Reveal>
          <Metrics telemetry={telemetry} rate={rate} loading={loading} />
          <div className="grid items-stretch gap-4 lg:grid-cols-[minmax(0,1fr)_310px] xl:grid-cols-[minmax(0,1fr)_340px]">
            <Reveal className="min-w-0 h-full">
              <TrafficChart
                samples={samples}
                loading={loading}
                rate={rate}
                state={telemetry?.replay_status ?? 'connecting'}
              />
            </Reveal>
            <Reveal delay={0.08} className="min-w-0 h-full">
              <ObservationContext telemetry={telemetry} loading={loading} />
            </Reveal>
          </div>
          <Reveal>
            <AlertFeed
              records={alerts}
              loading={loading}
              lateEvents={telemetry?.late_events ?? 0}
              live={connection === 'live'}
            />
          </Reveal>
          <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
            <Reveal className="min-w-0">
              <Coverage
                counts={telemetry?.alerts_by_class ?? {}}
                datasets={datasets}
                loading={loading}
              />
            </Reveal>
            <Reveal delay={0.08} className="min-w-0">
              <Benchmark />
            </Reveal>
          </div>
          <p className="rounded-2xl border border-white/8 bg-panel/40 px-5 py-4 text-[10px] leading-6 text-muted">
            Model scores are synthetic-trained posteriors or heuristic strengths; they are not
            calibrated probabilities of compromise. Public-source validation remains limited,
            including significant DGA false positives and unvalidated encrypted-malware detection.
            Evidence and analyst review are essential.
          </p>
        </div>
      </motion.main>
      <SiteFooter />
    </div>
  )
}
