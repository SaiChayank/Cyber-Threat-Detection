'use client'
import { motion } from 'motion/react'
import { MoveRight, CircleAlert, RefreshCw, Radio } from 'lucide-react'
import { useMonitor } from '@/hooks/use-monitor'
import { Button } from '@/components/ui/button'
import { Eyebrow } from '@/components/ui/panel'
import { BrandMark } from '@/components/brand'
import { SiteNav } from '@/components/site-nav'
import { SiteFooter } from '@/components/site-footer'
import { Reveal } from '@/components/reveal'
import { cn } from '@/lib/utils'
import { Metrics } from './metrics'
import { TrafficChart } from './traffic-chart'
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
        <div className="mx-auto max-w-[1440px] space-y-7 px-5 pt-10 pb-16 sm:px-8 lg:px-12">
          <header
            id="overview"
            className="relative flex flex-col justify-between gap-6 border-b border-white/8 pb-8 sm:flex-row sm:items-end"
          >
            <div>
              <Eyebrow className="flex items-center gap-2 text-accent">
                <MoveRight size={14} /> One-way intelligence
              </Eyebrow>
              <h1 className="mt-4 font-display text-[clamp(38px,5vw,66px)] leading-[1.05] font-medium tracking-[-.055em]">
                Every signal.
                <br className="sm:hidden" /> A clearer view<span className="text-accent">.</span>
              </h1>
              <p className="mt-4 max-w-xl text-sm leading-6 text-muted">
                Your observation layer in motion. Replay traffic, inspect detections and follow the
                evidence.
              </p>
            </div>
            <div
              role="status"
              className="flex w-fit shrink-0 items-center gap-2.5 rounded-full border border-white/10 bg-panel/60 px-4 py-3 text-[10px] backdrop-blur-md"
            >
              <Radio
                size={14}
                className={cn(connection === 'live' ? 'text-signal' : 'text-accent')}
              />
              {connection === 'live'
                ? 'Stream connected'
                : connection === 'connecting'
                  ? 'Connecting'
                  : 'Reconnecting'}
              <span className="mx-1 text-line">/</span>
              <span className="text-muted">LOCAL ENCLAVE</span>
            </div>
          </header>
          <div className="glass-panel flex items-start gap-4 rounded-2xl px-5 py-4">
            <BrandMark className="mt-0.5 h-7 w-7 text-white/80" />
            <div className="flex-1">
              <span className="text-[9px] font-semibold tracking-[.16em] text-accent">
                PASSIVE BY DESIGN
              </span>
              <p className="mt-1.5 text-[11px] leading-5 text-muted">
                One-way observation · Encrypted content stays opaque · Alerts never trigger network
                actions
              </p>
            </div>
            <span className="hidden rounded-full border border-white/10 px-3 py-2 text-[8px] tracking-[.1em] text-muted sm:block">
              LAB PROTOTYPE
            </span>
          </div>
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
          <Metrics telemetry={telemetry} rate={rate} loading={loading} />
          <Reveal>
            <TrafficChart samples={samples} loading={loading} rate={rate} />
          </Reveal>
          <Reveal>
            <ReplayControls
              datasets={datasets}
              state={telemetry?.replay_status ?? 'idle'}
              refresh={refresh}
              connected={!!telemetry && !error}
            />
          </Reveal>
          <Reveal>
            <Coverage
              counts={telemetry?.alerts_by_class ?? {}}
              datasets={datasets}
              loading={loading}
            />
          </Reveal>
          <Reveal>
            <AlertFeed
              records={alerts}
              loading={loading}
              lateEvents={telemetry?.late_events ?? 0}
              live={connection === 'live'}
            />
          </Reveal>
          <Reveal>
            <Benchmark />
          </Reveal>
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
