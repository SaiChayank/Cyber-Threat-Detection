'use client'
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '@/services/api'
import {
  alertSchema,
  type AlertRecord,
  type Dataset,
  type RateSample,
  type Telemetry,
} from '@/schemas/api'
import { formatTime } from '@/lib/utils'

export function useMonitor() {
  const [alerts, setAlerts] = useState<AlertRecord[]>([])
  const [telemetry, setTelemetry] = useState<Telemetry | null>(null)
  const [datasets, setDatasets] = useState<Dataset[]>([])
  const [samples, setSamples] = useState<RateSample[]>([])
  const [connection, setConnection] = useState<'connecting' | 'live' | 'reconnecting'>('connecting')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const refreshRef = useRef<() => Promise<void>>(async () => {})
  const refresh = useCallback(() => refreshRef.current(), [])
  useEffect(() => {
    const controller = new AbortController()
    let source: EventSource | null = null
    let timer: ReturnType<typeof setTimeout>
    let cursor = 0
    let initialized = false
    let previous: { at: number; processed: number } | null = null
    let fetching = false
    const alive = () => !controller.signal.aborted

    function connect() {
      if (!alive() || source) return
      source = new EventSource(`/api/stream?after=${cursor}`)
      source.onopen = () => {
        if (alive()) setConnection('live')
      }
      source.onerror = () => {
        if (alive()) setConnection('reconnecting')
      }
      source.onmessage = (event) => {
        if (!alive()) return
        try {
          const parsed = alertSchema.safeParse(JSON.parse(event.data))
          if (!parsed.success) {
            setError('An alert did not match the expected API schema.')
            return
          }
          const row = parsed.data
          cursor = Math.max(cursor, row.sequence)
          setAlerts((current) =>
            current.some((item) => item.sequence === row.sequence)
              ? current
              : [row, ...current].sort((a, b) => b.sequence - a.sequence).slice(0, 200),
          )
        } catch {
          setError('The stream delivered an unreadable alert. Retrying on the next update.')
        }
      }
    }
    async function load() {
      if (!alive() || fetching) return
      fetching = true
      try {
        if (!initialized) {
          const [rows, presets, nextTelemetry] = await Promise.all([
            api.alerts(controller.signal),
            api.datasets(controller.signal),
            api.telemetry(controller.signal),
          ])
          if (!alive()) return
          setAlerts(rows)
          setDatasets(presets)
          setTelemetry(nextTelemetry)
          cursor = rows.reduce((max, row) => Math.max(max, row.sequence), 0)
          previous = { at: Date.now(), processed: nextTelemetry.processed }
          initialized = true
          connect()
        } else {
          const next = await api.telemetry(controller.signal)
          if (!alive()) return
          const now = Date.now()
          const rate =
            previous && next.processed >= previous.processed
              ? Math.max(
                  0,
                  (next.processed - previous.processed) /
                    Math.max(0.001, (now - previous.at) / 1000),
                )
              : 0
          previous = { at: now, processed: next.processed }
          setSamples((current) =>
            [...current, { time: formatTime(now), rate: Math.round(rate * 10) / 10 }].slice(-24),
          )
          setTelemetry(next)
        }
        setError(null)
      } catch (exception) {
        if (alive()) {
          setConnection('reconnecting')
          setError(
            `Local API unavailable or incompatible. ${exception instanceof Error ? exception.message : 'Check the server output.'}`,
          )
        }
      } finally {
        fetching = false
        if (alive()) setLoading(false)
      }
    }
    refreshRef.current = load
    async function poll() {
      await load()
      if (alive()) timer = setTimeout(poll, 1500)
    }
    void poll()
    return () => {
      controller.abort()
      source?.close()
      clearTimeout(timer)
      refreshRef.current = async () => {}
    }
  }, [])
  return { alerts, telemetry, datasets, samples, connection, error, loading, refresh }
}
