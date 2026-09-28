'use client'
import { motion } from 'motion/react'
import { ShieldCheck, CircleAlert, RefreshCw } from 'lucide-react'
import { useMonitor } from '@/hooks/use-monitor'
import { Button } from '@/components/ui/button'
import { Eyebrow } from '@/components/ui/panel'
import { cn } from '@/lib/utils'
import { MonitorNav } from './shell'
import { Metrics } from './metrics'
import { TrafficChart } from './traffic-chart'
import { ReplayControls } from './replay-controls'
import { Coverage, Benchmark } from './coverage'
import { AlertFeed } from './alert-feed'

export function Monitor() {
  const { alerts, telemetry, datasets, samples, connection, error, loading, refresh } = useMonitor()
  const rate = samples.at(-1)?.rate ?? 0
  return (
    <div className="min-h-screen">
      <MonitorNav />
      <motion.main
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        id="main-content"
        className="lg:ml-[238px]"
      >
        <div
          id="overview"
          className="mx-auto max-w-[1600px] space-y-6 px-4 py-7 sm:px-7 lg:px-8 lg:py-9"
        >
          <header className="flex flex-col justify-between gap-5 sm:flex-row sm:items-center">
            <div>
              <Eyebrow>
                Network intelligence <span className="mx-2 text-line">/</span> Operations center
              </Eyebrow>
              <h1 className="mt-3 font-display text-3xl font-medium tracking-[-.045em] sm:text-4xl">
                Threat monitor<span className="text-lilac">.</span>
              </h1>
              <p className="mt-3 text-xs text-muted">
                A clearer view of passively observed traffic.
              </p>
            </div>
            <div
              role="status"
              className="flex w-fit items-center gap-2 rounded-full border border-line bg-panel px-4 py-2.5 text-[10px]"
            >
              <span
                className={cn(
                  'h-1.5 w-1.5 rounded-full',
                  connection === 'live' ? 'bg-lime shadow-[0_0_8px_#d5f5bd50]' : 'bg-amber-300',
                )}
              />
              {connection === 'live'
                ? 'Stream connected'
                : connection === 'connecting'
                  ? 'Connecting'
                  : 'Reconnecting'}
              <span className="mx-2 text-line">|</span>
              <span className="text-muted">LOCAL ENCLAVE</span>
            </div>
          </header>
          <div className="flex items-start gap-3 rounded-xl border border-lilac/15 bg-lilac/5 px-4 py-4">
            <ShieldCheck size={18} className="mt-0.5 shrink-0 text-lilac" />
            <div className="flex-1">
              <span className="text-[9px] font-semibold tracking-[.12em] text-lilac">
                PASSIVE MODE
              </span>
              <p className="mt-1 text-[11px] leading-5 text-muted">
                One-way observation · Encrypted content stays opaque · Alerts never trigger network
                actions
              </p>
            </div>
            <span className="hidden rounded-full border border-line px-2.5 py-1.5 text-[8px] text-muted sm:block">
              LAB PROTOTYPE
            </span>
          </div>
          {error && (
            <div
              role="alert"
              className="flex flex-wrap items-center gap-3 rounded-xl border border-rose-400/25 bg-rose-400/5 p-4 text-xs text-rose-300"
            >
              <CircleAlert size={16} />
              <p className="min-w-0 flex-1 leading-5">{error}</p>
              <Button variant="ghost" className="text-current" onClick={() => void refresh()}>
                <RefreshCw size={13} />
                Retry connection
              </Button>
            </div>
          )}
          {telemetry?.replay_error && (
            <div
              role="alert"
              className="rounded-xl border border-rose-400/25 bg-rose-400/5 p-4 text-xs leading-6 text-rose-300"
            >
              Replay failed: {telemetry.replay_error}
            </div>
          )}
          <Metrics telemetry={telemetry} rate={rate} loading={loading} />
          <TrafficChart samples={samples} loading={loading} rate={rate} />
          <ReplayControls
            datasets={datasets}
            state={telemetry?.replay_status ?? 'idle'}
            refresh={refresh}
            connected={!!telemetry && !error}
          />
          <Coverage
            counts={telemetry?.alerts_by_class ?? {}}
            datasets={datasets}
            loading={loading}
          />
          <AlertFeed
            records={alerts}
            loading={loading}
            lateEvents={telemetry?.late_events ?? 0}
            live={connection === 'live'}
          />
          <Benchmark />
          <p className="rounded-xl border border-line bg-panel px-5 py-4 text-[10px] leading-6 text-muted">
            Model scores are synthetic-trained posteriors or heuristic strengths; they are not
            calibrated probabilities of compromise. Public-source validation remains limited,
            including significant DGA false positives and unvalidated encrypted-malware detection.
            Evidence and analyst review are essential.
          </p>
          <footer className="flex flex-wrap justify-between gap-3 border-t border-line pt-5 text-[9px] text-muted">
            <span>PS26145 · Passive network threat intelligence</span>
            <span>One-way observation · No inline blocking · No payload decryption</span>
          </footer>
        </div>
      </motion.main>
    </div>
  )
}
