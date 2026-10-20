/* Actual hook regression: no browser driver, new package, or production mock API. */
const assert = require('node:assert/strict')
const { readFileSync } = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')
const { createRequire } = require('node:module')
const { test } = require('node:test')
const root = path.resolve(__dirname, '../..')
const requireFrontend = createRequire(path.join(root, 'frontend/package.json'))
const ts = requireFrontend('typescript')

function compile(name, modules, globals = {}) {
  const code = ts.transpileModule(readFileSync(path.join(root, name), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText
  const module = { exports: {} }
  vm.runInNewContext(code, {
    module, exports: module.exports,
    require: (id) => {
      assert.ok(Object.hasOwn(modules, id), `Unexpected dependency: ${id}`)
      return modules[id]
    },
    AbortController, Error, console, ...globals,
  }, { filename: name })
  return module.exports
}
const schemas = compile('frontend/src/schemas/api.ts', { zod: requireFrontend('zod') })
const row = (sequence) => ({ sequence, timestamp: 1700000000000 + sequence,
  flow_id: `contract-flow-${sequence}`, alert_id: `contract-alert-${sequence}`,
  threat_class: 'DDOS', severity: 'HIGH', confidence_score: .9,
  supporting_evidence: 'Controlled regression metadata', src_ip: '192.0.2.1',
  dst_ip: '198.51.100.1', src_port: null, dst_port: 443,
  detection_source: 'RULE', raw_evidence_metrics: {} })
const flush = () => new Promise((resolve) => setImmediate(resolve))

function harness(initial = [row(1)]) {
  const server = { rows: initial }
  const slots = [], effects = [], timers = [], streams = []
  let cursor = 0, mounted = false, alertsReads = 0
  const react = {
    useState(initialValue) {
      const index = cursor++
      if (!slots[index]) slots[index] = { value: initialValue }
      return [slots[index].value, (next) => {
        slots[index].value = typeof next === 'function' ? next(slots[index].value) : next
      }]
    },
    useRef(value) {
      const index = cursor++
      if (!slots[index]) slots[index] = { current: value }
      return slots[index]
    },
    useCallback: (callback) => callback,
    useEffect(effect) { if (!mounted) effects.push(effect) },
  }
  class Source {
    static OPEN = 1
    static CLOSED = 2
    constructor(url) { this.url = url; this.readyState = 0; streams.push(this) }
    open() { this.readyState = 1; this.onopen?.() }
    close() { this.readyState = 2 }
    emit(data) { if (this.readyState === 1) this.onmessage?.({ data }) }
  }
  const api = {
    async alerts() { alertsReads++; return schemas.alertSchema.array().parse([...server.rows].reverse()) },
    async datasets() { return [] },
    async telemetry() { return { processed: 3, processing_p95_ms: 0, active_sources: 1,
      late_events: 0, state_evictions: 0, replay_status: 'idle', replay_error: null,
      alerts_by_class: { DDOS: server.rows.length }, throughput_target: 2000, confidence_note: 'Test' } },
  }
  const { useMonitor } = compile('frontend/src/hooks/use-monitor.ts', {
    react, '@/services/api': { api }, '@/schemas/api': schemas,
    '@/lib/utils': { formatTime: () => 'test-time' },
  }, { EventSource: Source, setTimeout: (callback) => { timers.push(callback); return callback },
       clearTimeout: (callback) => { const index = timers.indexOf(callback); if (index >= 0) timers.splice(index, 1) } })
  const render = () => { cursor = 0; const state = useMonitor(); mounted = true; return state }
  render()
  const cleanups = effects.map((effect) => effect())
  return { server, streams, state: render, reads: () => alertsReads,
    async tick() { assert.ok(timers.length, 'A recovery poll must remain scheduled'); await timers.shift()(); await flush() },
    close() { cleanups.forEach((cleanup) => cleanup()) } }
}

test('initial incompatible history stays visible as an error and recovers without a reload', async () => {
  const h = harness([{ sequence: 1 }])
  try {
    await flush()
    assert.equal(h.state().unavailable, true)
    assert.equal(h.streams.length, 0)
    h.server.rows = [row(1)]
    await h.tick()
    h.streams.at(-1).open()
    assert.equal(h.state().alerts.length, 1)
    assert.equal(h.state().error, null)
  } finally { h.close() }
})

for (const input of ['schema', 'json']) {
  test(`invalid SSE ${input} cannot silently skip a repaired durable record`, async () => {
    const h = harness()
    try {
      await flush()
      const first = h.streams[0]
      first.open()
      const bad = { ...row(2) }
      delete bad.confidence_score
      h.server.rows = [row(1), bad, row(3)]
      const queued = first.onmessage
      first.emit(input === 'schema' ? JSON.stringify(bad) : '{')
      queued({ data: JSON.stringify(row(3)) }) // A stale queued callback must not hide the error.
      assert.ok(h.state().error, 'A later valid message must not hide incomplete history')
      assert.notEqual(h.state().connection, 'live')
      await h.tick()
      assert.equal(h.state().unavailable, true)
      assert.equal(h.state().alerts.length, 1, 'Retain the valid queue during repair')
      h.server.rows = [row(1), row(2), row(3)]
      await h.tick()
      h.streams.at(-1).open()
      const recovered = h.state()
      assert.equal(recovered.error, null)
      assert.deepEqual(Array.from(recovered.alerts, (value) => value.sequence), [3, 2, 1])
      assert.equal(new Set(recovered.alerts.map((value) => value.alert_id)).size, 3)
      assert.ok(h.reads() >= 3, 'Recovery must reconcile against durable REST history')
      const resumed = h.streams.at(-1)
      assert.equal(resumed.url, '/api/stream?after=3')
      first.onerror?.() // An obsolete connection must not close the new stream.
      queued({ data: JSON.stringify(row(2)) })
      assert.equal(h.state().connection, 'live')
      resumed.emit(JSON.stringify(row(3)))
      assert.equal(h.state().alerts.length, 3, 'Resume replay must not duplicate an analyst record')
      resumed.emit(JSON.stringify(row(4)))
      assert.deepEqual(Array.from(h.state().alerts, (value) => value.sequence), [4, 3, 2, 1])
    } finally { h.close() }
  })
}
