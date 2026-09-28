import { z } from 'zod'

export const alertSchema = z
  .object({
    sequence: z.number().int().nonnegative(),
    timestamp: z.number().nonnegative().max(8.64e15),
    flow_id: z.string(),
    alert_id: z.string(),
    threat_class: z.string(),
    severity: z.string(),
    confidence_score: z.number().min(0).max(1),
    supporting_evidence: z.string(),
    src_ip: z.string(),
    dst_ip: z.string(),
    src_port: z.number().nullable(),
    dst_port: z.number().nullable(),
    detection_source: z.string(),
    raw_evidence_metrics: z
      .record(z.string(), z.unknown())
      .nullable()
      .transform((value) => value || {}),
  })
  .passthrough()
export const telemetrySchema = z.object({
  processed: z.number(),
  processing_p95_ms: z.number(),
  active_sources: z.number(),
  late_events: z.number(),
  state_evictions: z.number(),
  replay_status: z.string(),
  replay_error: z.string().nullable(),
  alerts_by_class: z.record(z.string(), z.number()),
  throughput_target: z.number(),
  confidence_note: z.string(),
})
export const datasetSchema = z.object({
  id: z.string(),
  name: z.string(),
  ready: z.boolean(),
  event_limit: z.number(),
  model: z.string(),
})
export const healthSchema = z.object({
  status: z.string(),
  architecture: z.string(),
  threat_classes: z.array(z.string()),
})
export const benchmarkSchema = z.object({
  events: z.number(),
  alerts: z.number(),
  elapsed_seconds: z.number(),
  metadata_events_per_second: z.number(),
  throughput_target: z.number(),
  throughput_pass: z.boolean(),
  processing_and_persistence_p95_ms: z.number(),
  latency_target_ms: z.number(),
  latency_pass: z.boolean(),
  workload: z.string(),
  scope: z.string(),
  python: z.string(),
  platform: z.string(),
})
export const replaySchema = z.object({
  scenario: z.string().min(1, 'Choose a scenario'),
  speed: z.number().min(0.1, 'Minimum speed is 0.1×').max(10000, 'Maximum speed is 10,000×'),
})
export type AlertRecord = z.infer<typeof alertSchema>
export type Telemetry = z.infer<typeof telemetrySchema>
export type Dataset = z.infer<typeof datasetSchema>
export type ReplayConfig = z.infer<typeof replaySchema>
export type RateSample = { time: string; rate: number }
export type BenchmarkReport = z.infer<typeof benchmarkSchema>
