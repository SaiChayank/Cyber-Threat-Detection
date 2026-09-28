import { z } from 'zod'
import {
  alertSchema,
  benchmarkSchema,
  datasetSchema,
  healthSchema,
  telemetrySchema,
  type ReplayConfig,
} from '@/schemas/api'

async function request(path: string, options: RequestInit = {}): Promise<unknown> {
  const timeout = AbortSignal.timeout(10000)
  const signal = options.signal ? AbortSignal.any([options.signal, timeout]) : timeout
  const response = await fetch(path, { ...options, cache: 'no-store', signal })
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    const error = z.object({ detail: z.unknown() }).safeParse(body)
    throw new Error(
      error.success && typeof error.data.detail === 'string'
        ? error.data.detail
        : `Request failed (${response.status}). Please check the API.`,
    )
  }
  return body
}

export const api = {
  async health(signal?: AbortSignal) {
    return healthSchema.parse(await request('/api/health', { signal }))
  },
  async benchmark(signal?: AbortSignal) {
    return benchmarkSchema.parse(await request('/api/benchmark', { signal }))
  },
  async telemetry(signal?: AbortSignal) {
    return telemetrySchema.parse(await request('/api/telemetry', { signal }))
  },
  async alerts(signal?: AbortSignal) {
    return z
      .array(alertSchema)
      .parse(await request('/api/alerts?newest=true&limit=200', { signal }))
  },
  async datasets(signal?: AbortSignal) {
    return z.array(datasetSchema).parse(await request('/api/datasets', { signal }))
  },
  start(config: ReplayConfig, signal?: AbortSignal) {
    return request('/api/replay/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
      signal,
    })
  },
  stop(signal?: AbortSignal) {
    return request('/api/replay/stop', { method: 'POST', signal })
  },
  upload(file: File, speed: number, signal?: AbortSignal) {
    return request(`/api/replay/pcap?speed=${encodeURIComponent(speed)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/octet-stream' },
      body: file,
      signal,
    })
  },
}
