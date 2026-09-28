'use client'
import { useEffect, useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { AnimatePresence, motion } from 'motion/react'
import {
  Play,
  Square,
  Upload,
  LoaderCircle,
  CheckCircle2,
  CircleAlert,
  X,
  Database,
} from 'lucide-react'
import { Panel, Eyebrow } from '@/components/ui/panel'
import { Button } from '@/components/ui/button'
import { replaySchema, type ReplayConfig, type Dataset } from '@/schemas/api'
import { detectionModules } from '@/constants/threats'
import { api } from '@/services/api'
import { cn } from '@/lib/utils'

const inputClass =
  'min-h-11 w-full rounded-xl border border-line bg-ink px-3 text-xs text-white transition focus:border-accent disabled:opacity-40'
export function ReplayControls({
  datasets,
  state,
  refresh,
  connected,
}: {
  datasets: Dataset[]
  state: string
  refresh: () => Promise<void>
  connected: boolean
}) {
  const {
    register,
    handleSubmit,
    getValues,
    formState: { errors },
  } = useForm<ReplayConfig>({
    resolver: zodResolver(replaySchema),
    defaultValues: { scenario: 'ALL', speed: 100 },
  })
  const [busy, setBusy] = useState<'start' | 'stop' | 'upload' | null>(null)
  const [notice, setNotice] = useState<{ text: string; error: boolean } | null>(null)
  const abort = useRef<AbortController | null>(null)
  const running = state === 'running'
  useEffect(
    () => () => {
      abort.current?.abort()
    },
    [],
  )
  async function execute(
    action: 'start' | 'stop' | 'upload',
    operation: (signal: AbortSignal) => Promise<unknown>,
    message: string,
  ) {
    if (busy) return
    abort.current = new AbortController()
    setBusy(action)
    setNotice(null)
    try {
      await operation(abort.current.signal)
      if (!abort.current.signal.aborted) {
        setNotice({ text: message, error: false })
        await refresh()
      }
    } catch (exception) {
      if (!abort.current.signal.aborted)
        setNotice({
          text: exception instanceof Error ? exception.message : 'Request failed',
          error: true,
        })
    } finally {
      if (!abort.current.signal.aborted) setBusy(null)
    }
  }
  const start = handleSubmit((config) =>
    execute(
      'start',
      (signal) => api.start(config, signal),
      'Replay started. Alerts appear as events are processed.',
    ),
  )
  async function upload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0]
    event.currentTarget.value = ''
    if (!file) return
    if (file.size > 16 * 1024 * 1024) {
      setNotice({
        text: 'Capture limit is 16 MiB. Choose a smaller classic PCAP file.',
        error: true,
      })
      return
    }
    if (!file.name.toLowerCase().endsWith('.pcap')) {
      setNotice({ text: 'Choose a classic .pcap capture. PCAPNG is not supported.', error: true })
      return
    }
    const parsed = replaySchema.safeParse(getValues())
    if (!parsed.success) {
      setNotice({ text: parsed.error.issues[0].message, error: true })
      return
    }
    await execute(
      'upload',
      (signal) => api.upload(file, parsed.data.speed, signal),
      `${file.name} accepted for metadata-only replay.`,
    )
  }
  return (
    <section id="replay" className="scroll-mt-24">
      <Panel className="p-5 sm:p-6">
        <div className="flex flex-col justify-between gap-5 xl:flex-row xl:items-center">
          <div className="shrink-0">
            <Eyebrow>Controlled testing</Eyebrow>
            <h2 className="mt-2 font-display text-xl">Traffic replay</h2>
            <p className="mt-2 text-[11px] text-muted">
              Run a scenario or inspect a passive capture.
            </p>
          </div>
          <form
            onSubmit={start}
            className="grid gap-2 sm:grid-cols-[minmax(160px,1fr)_100px_auto_auto_auto] xl:max-w-[800px] xl:flex-1"
          >
            <div>
              <label htmlFor="scenario" className="sr-only">
                Scenario
              </label>
              <select
                id="scenario"
                {...register('scenario')}
                className={inputClass}
                disabled={running || !!busy || !connected}
              >
                <optgroup label="Synthetic metadata scenarios">
                  <option value="ALL">All threat scenarios</option>
                  <option value="BENIGN">Benign baseline</option>
                  {detectionModules.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                </optgroup>
                {datasets.length > 0 && (
                  <optgroup label="Public-source replay presets">
                    {datasets.map((item) => (
                      <option key={item.id} value={item.id} disabled={!item.ready}>
                        {item.name}
                        {item.ready ? '' : ' (not downloaded)'}
                      </option>
                    ))}
                  </optgroup>
                )}
              </select>
            </div>
            <div>
              <label htmlFor="speed" className="sr-only">
                Replay speed
              </label>
              <select
                id="speed"
                {...register('speed', { valueAsNumber: true })}
                className={inputClass}
                disabled={running || !!busy || !connected}
              >
                {[1, 20, 100, 1000].map((speed) => (
                  <option key={speed} value={speed}>
                    {speed}× speed
                  </option>
                ))}
              </select>
            </div>
            <Button variant="primary" type="submit" disabled={running || !!busy || !connected}>
              {busy === 'start' ? (
                <LoaderCircle size={14} className="animate-spin" />
              ) : (
                <Play size={14} />
              )}
              Start replay
            </Button>
            <Button
              type="button"
              disabled={!running || !!busy || !connected}
              onClick={() =>
                void execute(
                  'stop',
                  (signal) => api.stop(signal),
                  'Replay stopped. Recorded alerts are preserved.',
                )
              }
            >
              {busy === 'stop' ? (
                <LoaderCircle size={13} className="animate-spin" />
              ) : (
                <Square size={12} />
              )}
              Stop
            </Button>
            <label
              className={cn(
                'relative flex min-h-11 items-center justify-center gap-2 overflow-hidden rounded-xl border border-line bg-panel px-4 text-xs font-medium focus-within:outline-2 focus-within:outline-accent',
                running || busy || !connected
                  ? 'opacity-40'
                  : 'cursor-pointer hover:border-accent/50',
              )}
            >
              <input
                type="file"
                accept=".pcap"
                aria-label="Replay a PCAP capture"
                onChange={upload}
                disabled={running || !!busy || !connected}
                className="absolute inset-0 w-full cursor-pointer opacity-0"
              />
              {busy === 'upload' ? (
                <LoaderCircle size={14} className="animate-spin" />
              ) : (
                <Upload size={14} />
              )}
              PCAP
            </label>
          </form>
        </div>
        {(errors.scenario || errors.speed) && (
          <p role="alert" className="mt-3 text-xs text-accent">
            {errors.scenario?.message || errors.speed?.message}
          </p>
        )}
        <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-line pt-4 text-[9px] text-muted">
          <span className="flex items-center gap-1.5">
            <Database size={11} />
            {datasets.filter((item) => item.ready).length} public-source presets ready
          </span>
          <span>Classic Ethernet PCAP · 16 MiB maximum</span>
          <span>Replay speed scales recorded event intervals</span>
        </div>
      </Panel>
      <AnimatePresence>
        {notice && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div
              role={notice.error ? 'alert' : 'status'}
              className={cn(
                'mt-3 flex items-center gap-3 rounded-xl border px-4 py-3 text-xs leading-5',
                notice.error
                  ? 'border-brand/20 bg-brand/5 text-accent'
                  : 'border-signal/20 bg-signal/5 text-signal',
              )}
            >
              {notice.error ? (
                <CircleAlert size={15} className="shrink-0" />
              ) : (
                <CheckCircle2 size={15} className="shrink-0" />
              )}
              <span className="flex-1">{notice.text}</span>
              <Button
                variant="ghost"
                className="h-8 min-h-8 w-8 p-1 text-current"
                aria-label="Dismiss replay notification"
                onClick={() => setNotice(null)}
              >
                <X size={14} />
              </Button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  )
}
