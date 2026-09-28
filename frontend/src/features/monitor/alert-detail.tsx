'use client'
import { useEffect, useRef, useState } from 'react'
import * as Dialog from '@radix-ui/react-dialog'
import { X, Copy, Check, Fingerprint, ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Eyebrow } from '@/components/ui/panel'
import { threatName } from '@/constants/threats'
import { evidenceValue } from '@/lib/utils'
import type { AlertRecord } from '@/schemas/api'
import { Severity } from './severity'

export function AlertDetail({
  alert,
  onClose,
}: {
  alert: AlertRecord | null
  onClose: () => void
}) {
  const [copied, setCopied] = useState(false)
  const [copyError, setCopyError] = useState(false)
  const returnFocus = useRef<HTMLButtonElement | null>(null)
  useEffect(() => {
    if (alert)
      returnFocus.current = document.querySelector<HTMLButtonElement>(
        `[data-alert="${alert.sequence}"]`,
      )
  }, [alert])
  async function copy() {
    if (!alert) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(alert, null, 2))
      setCopied(true)
      setCopyError(false)
    } catch {
      setCopyError(true)
    }
  }
  return (
    <Dialog.Root
      open={!!alert}
      onOpenChange={(open) => {
        if (!open) {
          setCopied(false)
          setCopyError(false)
          onClose()
        }
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay fixed inset-0 z-60 bg-black/75 backdrop-blur-sm" />
        <Dialog.Content
          className="dialog-content fixed top-1/2 left-1/2 z-70 max-h-[88dvh] w-[calc(100%-32px)] max-w-[680px] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-2xl border border-line bg-[#110e19] p-5 shadow-2xl focus:outline-none sm:p-7"
          onCloseAutoFocus={(event) => {
            event.preventDefault()
            if (returnFocus.current?.isConnected) returnFocus.current.focus()
            else document.querySelector<HTMLInputElement>('[aria-label="Search alerts"]')?.focus()
          }}
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <Eyebrow>Alert investigation</Eyebrow>
              <Dialog.Title className="mt-3 font-display text-2xl tracking-[-.035em]">
                {alert ? threatName(alert.threat_class) : 'Alert detail'}
              </Dialog.Title>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" className="w-11 px-0" aria-label="Close alert detail">
                <X size={18} />
              </Button>
            </Dialog.Close>
          </div>
          <Dialog.Description className="mt-3 text-xs leading-6 text-muted">
            Review the observed connection and supporting metadata. A detection indicates suspicion
            and requires analyst interpretation.
          </Dialog.Description>
          {alert && (
            <div className="mt-6 space-y-6">
              <div className="flex flex-wrap items-center gap-3 rounded-xl border border-line bg-ink p-4">
                <Severity severity={alert.severity} />
                <strong className="text-sm">
                  {(alert.confidence_score * 100).toFixed(1)}% confidence score
                </strong>
                <span className="rounded bg-lilac/10 px-2 py-1 text-[10px] text-lilac">
                  {alert.detection_source}
                </span>
                <p className="w-full text-[10px] text-muted">
                  Score basis:{' '}
                  {evidenceValue(
                    alert.raw_evidence_metrics.confidence_kind ?? 'Uncalibrated detector score',
                  )}
                </p>
              </div>
              <section>
                <h3 className="text-xs font-semibold text-white">Observed connection</h3>
                <div className="mt-3 flex flex-wrap items-center gap-2 font-mono text-xs text-lilac">
                  <span>
                    {alert.src_ip}:{alert.src_port ?? '—'}
                  </span>
                  <ArrowRight size={13} />
                  <span>
                    {alert.dst_ip}:{alert.dst_port ?? '—'}
                  </span>
                </div>
                <p className="mt-2 text-[10px] text-muted">
                  {new Date(alert.timestamp).toISOString()} · captured event time
                </p>
              </section>
              <section>
                <h3 className="text-xs font-semibold">Supporting evidence</h3>
                <p className="mt-3 rounded-xl border border-line bg-ink p-4 text-xs leading-6 break-words text-muted">
                  {alert.supporting_evidence}
                </p>
                <dl className="mt-3 grid gap-2 sm:grid-cols-2">
                  {Object.entries(alert.raw_evidence_metrics).map(([key, value]) => (
                    <div key={key} className="min-w-0 rounded-xl border border-line p-3">
                      <dt className="text-[9px] tracking-[.04em] text-muted uppercase">
                        {key.replaceAll('_', ' ')}
                      </dt>
                      <dd className="mt-2 text-xs font-medium break-words text-white">
                        {evidenceValue(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </section>
              <section>
                <h3 className="flex items-center gap-2 text-xs font-semibold">
                  <Fingerprint size={14} className="text-lilac" />
                  Identifiers
                </h3>
                <dl className="mt-3 space-y-2 font-mono text-[10px] break-all text-muted">
                  <div>
                    <dt className="inline">Flow: </dt>
                    <dd className="inline">{alert.flow_id}</dd>
                  </div>
                  <div>
                    <dt className="inline">Alert: </dt>
                    <dd className="inline">{alert.alert_id}</dd>
                  </div>
                </dl>
              </section>
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line pt-5">
                <p className="max-w-[360px] text-[10px] leading-5 text-muted">
                  Encrypted content stays opaque. Scores are synthetic-trained posteriors or
                  heuristic strengths, without deployment calibration.
                </p>
                <Button onClick={copy} className="text-xs">
                  {copied ? <Check size={13} /> : <Copy size={13} />}{' '}
                  {copied ? 'Copied' : 'Copy JSON'}
                </Button>
              </div>
              {copyError && (
                <p role="alert" className="text-xs text-rose-300">
                  Clipboard unavailable. Use the alert table’s JSON export.
                </p>
              )}
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  )
}
