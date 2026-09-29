'use client'
import { useId, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { Database, CheckCircle2, CircleAlert, ChevronDown } from 'lucide-react'
import { Skeleton } from '@/components/ui/panel'
import { formatNumber } from '@/lib/utils'
import type { Dataset } from '@/schemas/api'

export function DatasetReadiness({ datasets, loading }: { datasets: Dataset[]; loading: boolean }) {
  const [open, setOpen] = useState(false)
  const contentId = useId()
  const reducedMotion = useReducedMotion()
  return (
    <div className="mt-5 overflow-hidden rounded-xl border border-white/10 bg-ink/30">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={contentId}
        onClick={() => setOpen(!open)}
        className="flex min-h-14 w-full items-center gap-2.5 p-4 text-left text-[11px] transition hover:bg-white/3"
      >
        <Database size={14} className="shrink-0 text-accent" />
        <span className="flex-1">Public-source dataset readiness</span>
        <span className="text-[9px] text-muted">
          {loading
            ? '…'
            : `${datasets.filter((dataset) => dataset.ready).length}/${datasets.length} ready`}
        </span>
        <motion.span
          aria-hidden="true"
          animate={{ rotate: open ? 180 : 0 }}
          transition={reducedMotion ? { duration: 0 } : undefined}
        >
          <ChevronDown size={14} />
        </motion.span>
      </button>
      <div id={contentId}>
        <AnimatePresence initial={false}>
          {open && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={reducedMotion ? { duration: 0 } : undefined}
              className="overflow-hidden"
            >
              <div className="space-y-3 px-4 pb-4">
                {loading ? (
                  <Skeleton className="h-20 w-full" />
                ) : datasets.length ? (
                  datasets.map((dataset) => (
                    <div
                      key={dataset.id}
                      className="flex items-start gap-3 border-t border-white/8 pt-3 text-[11px]"
                    >
                      <span className="mt-0.5 shrink-0 text-signal">
                        {dataset.ready ? (
                          <CheckCircle2 size={13} />
                        ) : (
                          <CircleAlert size={13} className="text-accent" />
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
                  <p className="text-xs text-muted">
                    Dataset status will appear when the API connects.
                  </p>
                )}
                <p className="text-[10px] leading-5 text-muted">
                  UMUDGA provides real domain strings with simulated DNS timing. CIC DNS presets
                  replay captured metadata. IoT-23 is excluded because authorization was not
                  provided.
                </p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}
