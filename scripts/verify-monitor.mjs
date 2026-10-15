// Optional browser test tool; no application dependency is added.
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

if (!process.argv.includes('--isolated-api')) {
  throw new Error('Use --isolated-api only with a disposable ALERT_DB. Tests append replay alerts.')
}
const base = process.env.UI_BASE_URL || 'http://127.0.0.1:3000'
assert.ok(['localhost', '127.0.0.1'].includes(new URL(base).hostname), 'Use a loopback test server')
const output = path.resolve(process.env.UI_OUTPUT_DIR || 'artifacts/ui-pass')
await mkdir(output, { recursive: true })

async function browserTool() {
  // npm exec --package=playwright puts the optional tool's .bin directory on PATH.
  for (const bin of (process.env.PATH || '').split(path.delimiter)) {
    const module = path.resolve(bin, '..', 'playwright', 'index.mjs')
    if (existsSync(module)) return import(pathToFileURL(module).href)
  }
  return import('playwright')
}
const { chromium } = await browserTool()
const browser = process.env.UI_CDP_URL
  ? await chromium.connectOverCDP(process.env.UI_CDP_URL)
  : await chromium.launch({ channel: process.env.UI_BROWSER_CHANNEL || 'chrome', headless: true })
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
await context.addInitScript(() => {
  window.__uiStreams = []
  window.__uiReceived = []
  const NativeEventSource = window.EventSource
  window.EventSource = class extends NativeEventSource {
    constructor(...args) {
      super(...args)
      window.__uiStreams.push(this)
      this.addEventListener('message', (event) => {
        try {
          window.__uiReceived.push(JSON.parse(event.data))
        } catch {
          /* Invalid-input regression. */
        }
      })
    }
  }
})
const page = await context.newPage()
page.setDefaultTimeout(15000)
const results = []
const errors = []
let faultInjection = false
page.on('pageerror', (error) => errors.push(`Runtime: ${error.message}`))
page.on('console', (message) => {
  if (message.type() !== 'error') return
  // Deliberate unavailable/invalid-input tests produce expected HTTP failures.
  if (faultInjection && /Failed to load resource|ERR_|EventSource/.test(message.text())) return
  errors.push(`Console: ${message.text()}`)
})

async function test(name, run) {
  try {
    await run()
    results.push({ name, passed: true })
    console.log(`PASS ${name}`)
  } catch (error) {
    results.push({ name, passed: false, error: error.message })
    console.error(`FAIL ${name}: ${error.message}`)
    await page
      .screenshot({ path: path.join(output, `failure-${results.length}.png`) })
      .catch(() => {})
  }
}
async function until(read, predicate, message, timeout = 15000) {
  const end = Date.now() + timeout
  while (Date.now() < end) {
    const value = await read()
    if (predicate(value)) return value
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(message)
}
async function api(route, options) {
  const response = await context.request.fetch(`${base}/api/${route}`, options)
  assert.ok(response.ok(), `${route}: ${response.status()} ${await response.text()}`)
  return response.json()
}
const status = () => page.locator('#overview [role=status]').innerText()
const ready = () => until(status, (value) => value.includes('Stream connected'), 'Stream not live')
const rows = () => page.locator('[data-alert]').count()
const empty = page.getByRole('heading', { name: 'Ready to observe.', exact: true })
const scenario = page.getByLabel('Scenario', { exact: true })
const speed = page.getByLabel('Replay speed', { exact: true })
const start = page.getByRole('button', { name: 'Start replay', exact: true })
const stop = page.getByRole('button', { name: 'Stop', exact: true })

function pcap() {
  // Same classic Ethernet IPv4/TCP SYN fixture as the backend upload regressions.
  const header = Buffer.alloc(24)
  header.writeUInt32BE(0xa1b2c3d4)
  header.writeUInt16BE(2, 4)
  header.writeUInt16BE(4, 6)
  header.writeUInt32BE(65535, 16)
  header.writeUInt32BE(1, 20)
  const frame = Buffer.from(
    '0000000000000000000000000800450000280001000040060000c0000201c6336402c00001bb00000001000000005002ffff00000000',
    'hex',
  )
  const packets = [0, 1, 2].map((index) => {
    const entry = Buffer.alloc(16)
    entry.writeUInt32BE(1700000000 + index * 5)
    entry.writeUInt32BE(frame.length, 8)
    entry.writeUInt32BE(frame.length, 12)
    return Buffer.concat([entry, frame])
  })
  return Buffer.concat([header, ...packets])
}
async function upload(name, buffer) {
  await page.getByLabel('Replay a PCAP capture').setInputFiles({
    name,
    mimeType: 'application/octet-stream',
    buffer,
  })
}
async function submit(index) {
  return api('events', {
    method: 'POST',
    data: {
      timestamp: 1800000000000 + index * 31000,
      src_ip: `192.0.2.${(index % 254) + 1}`,
      dst_ip: '198.51.100.1',
      protocol: 17,
      dst_port: 443,
      packets: 12000,
      bytes: 720000,
      flow_id: `ui-regression-${index}`,
    },
  })
}
async function bounds(locator) {
  const box = await locator.boundingBox()
  assert.ok(box, 'Element has no visible bounds')
  const size = page.viewportSize()
  assert.ok(box.x >= -1 && box.x + box.width <= size.width + 1, 'Element clips horizontally')
}
async function layout() {
  // Recharts' ResizeObserver updates on the next frame after viewport changes.
  const dimensions = await until(
    () =>
      page.evaluate(() => ({
        width: document.documentElement.clientWidth,
        scroll: document.documentElement.scrollWidth,
      })),
    (value) => value.scroll <= value.width + 1,
    'Page has horizontal overflow',
    3000,
  )
  assert.ok(dimensions.scroll <= dimensions.width + 1, 'Page has horizontal overflow')
  await bounds(scenario)
  await bounds(start)
}
async function navigateSection(id, label) {
  if (page.viewportSize().width < 1280) {
    await page.getByRole('button', { name: 'Open menu', exact: true }).click()
    await page
      .getByRole('navigation', { name: 'Mobile navigation', exact: true })
      .getByRole('link', { name: label, exact: true })
      .click()
    assert.equal(await page.getByRole('button', { name: 'Open menu', exact: true }).count(), 1)
  } else {
    await page
      .getByRole('navigation', { name: 'Monitor navigation', exact: true })
      .getByRole('link', { name: label, exact: true })
      .click()
  }
  await until(
    () =>
      page.evaluate((section) => {
        const rect = document.getElementById(section).getBoundingClientRect()
        const header = document.querySelector('header').getBoundingClientRect()
        return rect.top >= header.bottom - 2 && rect.top < innerHeight
      }, id),
    Boolean,
    `Section ${id} is obscured by navigation`,
  )
}

try {
  assert.equal((await api('alerts')).length, 0, 'Start the test API with an empty disposable DB')
  await test('Initial live connection and empty state', async () => {
    await page.goto(`${base}/monitor`)
    await ready()
    await empty.waitFor()
    assert.equal(await start.isEnabled(), true)
    assert.equal(await stop.isDisabled(), true)
    assert.equal(await page.getByRole('button', { name: 'Export JSON' }).isDisabled(), true)
  })
  for (const [width, height] of [
    [1440, 1000],
    [768, 1024],
    [390, 844],
    [320, 740],
  ]) {
    await test(`${width}px empty state and section navigation`, async () => {
      await page.setViewportSize({ width, height })
      await layout()
      await navigateSection('alerts', 'Alert stream')
      await bounds(empty)
      await navigateSection('replay', 'Traffic replay')
      if (width < 1280) {
        const toggle = page.getByRole('button', { name: 'Open menu', exact: true })
        await toggle.click()
        await page.keyboard.press('Escape')
        assert.equal(await toggle.getAttribute('aria-expanded'), 'false')
        assert.equal(await toggle.evaluate((node) => node === document.activeElement), true)
      }
    })
  }
  await page.setViewportSize({ width: 1440, height: 1000 })
  await test('Scenario selection, incremental start/stop and metric updates', async () => {
    await scenario.selectOption('BOTNET_C2')
    await speed.selectOption('1')
    await start.click()
    await until(() => stop.isEnabled(), Boolean, 'Stop did not become available')
    assert.equal(await scenario.isDisabled(), true)
    const running = await api('telemetry')
    assert.equal(running.replay_status, 'running')
    assert.ok(running.processed > 0 && running.processed < 32)
    await until(
      () =>
        page
          .getByRole('region', { name: 'Live telemetry' })
          .locator('strong')
          .first()
          .locator('.sr-only')
          .innerText(),
      (value) => Number(value.replaceAll(',', '')) > 0,
      'Metrics did not update',
    )
    await stop.click()
    await until(() => start.isEnabled(), Boolean, 'Replay did not stop')
    const stopped = await api('telemetry')
    assert.equal(stopped.replay_status, 'stopped')
    await new Promise((resolve) => setTimeout(resolve, 400))
    assert.equal((await api('telemetry')).processed, stopped.processed)
  })
  await test('Replay restart, completion, SSE alerts and metric counts', async () => {
    await scenario.selectOption('ALL')
    await speed.selectOption('1000')
    await start.click()
    const telemetry = await until(
      () => api('telemetry'),
      (state) => state.replay_status === 'complete',
      'Replay did not complete',
    )
    assert.equal(telemetry.processed, 256)
    await until(rows, (count) => count > 0, 'SSE did not populate alert table')
    await until(
      () => page.getByRole('region', { name: 'Live telemetry' }).innerText(),
      (value) => value.includes('256'),
      'Processed metric is stale',
    )
    await until(
      () => page.locator('[aria-label="Observed event rate chart"] svg').count(),
      (count) => count > 0,
      'Chart did not render',
    )
    assert.equal(await stop.isDisabled(), true)
  })
  await test('Threat/severity/search filters, pagination, no-match recovery and JSON export', async () => {
    const threat = page.getByLabel('Filter threat class')
    const severity = page.getByLabel('Filter severity')
    const search = page.getByRole('searchbox', { name: 'Search alerts' })
    await threat.selectOption('DGA_DOMAINS')
    await until(rows, (count) => count > 0, 'No DGA alerts available')
    const expected = (await api('alerts?newest=true&limit=200')).filter(
      (row) => row.threat_class === 'DGA_DOMAINS',
    )
    assert.ok(expected.length > 0)
    const downloadPromise = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export JSON' }).click()
    const download = await downloadPromise
    const exported = JSON.parse(await readFile(await download.path(), 'utf8'))
    assert.deepEqual(
      exported.map((row) => row.alert_id),
      expected.map((row) => row.alert_id),
    )
    assert.ok(exported.every((row) => row.supporting_evidence && row.raw_evidence_metrics))
    await severity.selectOption(expected[0].severity)
    assert.ok((await rows()) > 0)
    await search.fill(expected[0].flow_id)
    assert.ok((await rows()) > 0)
    await search.fill('this-search-has-no-matching-alert')
    await page.getByRole('heading', { name: 'No matching signals.' }).waitFor()
    assert.equal(await page.getByRole('button', { name: 'Export JSON' }).isDisabled(), true)
    await page.getByRole('button', { name: 'Clear filters' }).click()
    assert.equal(await search.inputValue(), '')
    assert.equal(await threat.inputValue(), '')
    assert.equal(await severity.inputValue(), '')
    const first = await page.locator('[data-alert]').first().getAttribute('data-alert')
    await page.getByRole('button', { name: 'Next alert page' }).click()
    await until(
      () => page.locator('[data-alert]').first().getAttribute('data-alert'),
      (sequence) => sequence !== first,
      'Next page did not update',
    )
    await page.getByRole('button', { name: 'Previous alert page' }).click()
    await until(
      () => page.locator('[data-alert]').first().getAttribute('data-alert'),
      (sequence) => sequence === first,
      'Previous page did not update',
    )
  })
  for (const [width, height] of [
    [1440, 1000],
    [768, 1024],
    [390, 844],
    [320, 740],
  ]) {
    await test(`${width}px populated table, alert detail and focus return`, async () => {
      await page.setViewportSize({ width, height })
      await layout()
      await navigateSection('alerts', 'Alert stream')
      const inspect = page.locator('[data-alert]').first()
      await inspect.click()
      const dialog = page.getByRole('dialog')
      await dialog.waitFor()
      await bounds(dialog)
      assert.equal(
        await dialog.evaluate((node) => node.scrollWidth <= node.clientWidth + 1),
        true,
        'Alert detail has horizontal overflow',
      )
      await page.getByRole('heading', { name: 'Supporting evidence', exact: true }).waitFor()
      await page.keyboard.press('Escape')
      await dialog.waitFor({ state: 'hidden' })
      assert.equal(await inspect.evaluate((node) => node === document.activeElement), true)
      await page.locator('#alerts').screenshot({ path: path.join(output, `alerts-${width}.png`) })
    })
  }
  await test('IPv6 addresses and long identifiers fit mobile alert detail', async () => {
    const [ipv6] = await api('events', {
      method: 'POST',
      data: {
        timestamp: 1790000000000,
        src_ip: '2001:db8:1234:5678:abcd:ef12:3456:789a',
        dst_ip: '2001:db8:abcd:ef12:1234:5678:abcd:ef12',
        protocol: 17,
        packets: 12000,
        bytes: 720000,
        flow_id: 'ipv6-' + 'x'.repeat(100),
      },
    })
    await until(
      () => page.locator('[data-alert]').first().getAttribute('data-alert'),
      (sequence) => Number(sequence) === ipv6.sequence,
      'IPv6 alert did not arrive',
    )
    await page.locator('[data-alert]').first().click()
    const dialog = page.getByRole('dialog')
    await dialog.waitFor()
    await until(
      () => dialog.evaluate((node) => node.scrollWidth <= node.clientWidth + 1),
      Boolean,
      'IPv6 text clips in the mobile dialog',
      3000,
    )
    await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await dialog.getByRole('button', { name: 'Copy JSON', exact: true }).click()
    await dialog.getByRole('button', { name: 'Copied', exact: true }).waitFor()
    const copied = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()))
    assert.equal(copied.src_ip, '2001:db8:1234:5678:abcd:ef12:3456:789a')
    await page.keyboard.press('Escape')
    await dialog.waitFor({ state: 'hidden' })
  })
  await test('PCAP file input: invalid extension/empty/invalid/oversized and valid upload', async () => {
    await page.setViewportSize({ width: 390, height: 844 })
    await navigateSection('replay', 'Traffic replay')
    faultInjection = true
    await upload('invalid.txt', Buffer.from('not a capture'))
    await page.getByText('Choose a classic .pcap capture. PCAPNG is not supported.').waitFor()
    await upload('empty.pcap', Buffer.alloc(0))
    await page.getByText(/complete 24-byte header/).waitFor()
    await upload('invalid.pcap', Buffer.alloc(100, 'x'))
    await page.getByText(/capture format/).waitFor()
    await upload('oversized.pcap', Buffer.alloc(16 * 1024 * 1024 + 1))
    await page.getByText('Capture limit is 16 MiB. Choose a smaller classic PCAP file.').waitFor()
    const broken = pcap().subarray(0, 42)
    await upload('truncated.pcap', broken)
    await page.getByText(/Replay failed:.*truncated packet/i).waitFor()
    await upload('valid.pcap', pcap())
    await page.getByText('valid.pcap accepted for metadata-only replay.').waitFor()
    const telemetry = await until(
      () => api('telemetry'),
      (value) => value.replay_status === 'complete',
      'PCAP replay did not complete',
    )
    assert.equal(telemetry.processed, 3)
    faultInjection = false
  })
  await test('Telemetry unavailable/retry recovers the live status', async () => {
    faultInjection = true
    await page.route('**/api/telemetry', (route) =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Temporary API outage' }),
      }),
    )
    await page.getByText(/Local API unavailable/).waitFor()
    assert.equal(await start.isDisabled(), true)
    await page.unroute('**/api/telemetry')
    await page.getByRole('button', { name: 'Retry connection' }).click()
    await ready()
    assert.equal(await start.isEnabled(), true)
    faultInjection = false
  })
  await test('SSE-only disconnect/resume receives persisted alerts without duplicate records', async () => {
    await page.reload()
    await ready()
    const before = await api('alerts?newest=true&limit=200')
    const downloadPromise = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export JSON' }).click()
    const exported = JSON.parse(await readFile(await (await downloadPromise).path(), 'utf8'))
    assert.equal(exported.length, before.length)
    faultInjection = true
    await page.route('**/api/stream**', (route) =>
      route.fulfill({ status: 503, contentType: 'text/plain', body: 'Temporary stream outage' }),
    )
    // CLOSED is terminal for native EventSource (e.g. a proxy returning non-200).
    await page.evaluate(() => {
      const source = window.__uiStreams.at(-1)
      source.close()
      source.dispatchEvent(new Event('error'))
    })
    await until(status, (value) => value.includes('Reconnecting'), 'No reconnect feedback')
    const added = []
    for (let index = 0; index < 3; index++) added.push(...(await submit(index)))
    assert.equal(added.length, 3)
    await page.unroute('**/api/stream**')
    await ready()
    await until(
      () => page.evaluate(() => window.__uiReceived.map((row) => row.alert_id)),
      (ids) => added.every((row) => ids.includes(row.alert_id)),
      'Disconnected alerts were lost',
    )
    const after = await api('alerts?newest=true&limit=200')
    assert.equal(after.length, before.length + 3)
    await page.getByText(`JSON export generated with ${before.length} matching records.`).waitFor()
    const ids = await page
      .locator('[data-alert]')
      .evaluateAll((nodes) => nodes.map((node) => node.getAttribute('data-alert')))
    assert.equal(new Set(ids).size, ids.length)
    faultInjection = false
  })
  await test('Stream schema errors survive telemetry polling and recover on a valid event', async () => {
    await page.evaluate(() =>
      window.__uiStreams
        .at(-1)
        .dispatchEvent(new MessageEvent('message', { data: JSON.stringify({ invalid: true }) })),
    )
    const error = page.getByText('An alert did not match the expected API schema.')
    await error.waitFor()
    assert.equal(await start.isEnabled(), true, 'A stream error must not disable a healthy API')
    await new Promise((resolve) => setTimeout(resolve, 1800))
    assert.equal(await error.isVisible(), true)
    const persisted = await api('alerts?newest=true&limit=1')
    await page.evaluate(
      (row) =>
        window.__uiStreams
          .at(-1)
          .dispatchEvent(new MessageEvent('message', { data: JSON.stringify(row) })),
      persisted[0],
    )
    await error.waitFor({ state: 'hidden' })
  })
  await test('Initial backend unavailable state and subsequent recovery', async () => {
    faultInjection = true
    await page.route('**/api/**', (route) =>
      route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'API offline' }),
      }),
    )
    await page.reload()
    await page.getByText(/Local API unavailable/).waitFor()
    assert.equal(await start.isDisabled(), true)
    assert.equal(await page.getByLabel('Replay a PCAP capture').isDisabled(), true)
    assert.equal(await page.getByRole('button', { name: 'Export JSON' }).isDisabled(), true)
    await page.getByRole('heading', { name: 'Waiting for the local API.', exact: true }).waitFor()
    await bounds(page.getByRole('heading', { name: 'Waiting for the local API.', exact: true }))
    // Exercise Retry while unavailable. Automatic recovery can remove this button
    // before a click finishes scrolling if the routes are restored first.
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }))
    await page.getByRole('button', { name: 'Retry connection' }).click()
    await page.unroute('**/api/**')
    await ready()
    await until(rows, (count) => count > 0, 'Persisted alerts did not reload')
    faultInjection = false
  })
  await test('Held queue stays stable while real alerts persist and SSE/metrics continue', async () => {
    await page.setViewportSize({ width: 1440, height: 1000 })
    const before = await api('alerts?newest=true&limit=200')
    const displayedIds = () =>
      page
        .locator('[data-alert]')
        .evaluateAll((nodes) => nodes.map((node) => node.getAttribute('data-alert')))
    const originalIds = await displayedIds()
    const processed = (await api('telemetry')).processed
    await page.getByRole('button', { name: 'Hold queue', exact: true }).click()
    assert.equal(
      await page
        .getByRole('button', { name: 'Resume queue', exact: true })
        .getAttribute('aria-pressed'),
      'true',
    )
    const added = []
    for (let index = 200; index < 203; index++) added.push(...(await submit(index)))
    assert.equal(added.length, 3)
    await page.getByText('Queue held. 3 newer loaded alerts.', { exact: false }).waitFor()
    await until(
      () => page.evaluate(() => window.__uiReceived.map((row) => row.alert_id)),
      (ids) => added.every((row) => ids.includes(row.alert_id)),
      'Held queue interrupted SSE delivery',
    )
    assert.equal((await api('telemetry')).processed, processed + 3)
    assert.deepEqual(await displayedIds(), originalIds)
    const heldDownload = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export JSON', exact: true }).click()
    const held = JSON.parse(await readFile(await (await heldDownload).path(), 'utf8'))
    assert.deepEqual(
      held.map((row) => row.alert_id),
      before.map((row) => row.alert_id),
    )
    await page.getByRole('button', { name: 'Resume queue', exact: true }).click()
    await until(
      displayedIds,
      (ids) => added.every((row) => ids.includes(String(row.sequence))),
      'Resume did not include queued alerts',
    )
    const resumedDownload = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export JSON', exact: true }).click()
    const resumed = JSON.parse(await readFile(await (await resumedDownload).path(), 'utf8'))
    assert.equal(resumed.length, before.length + 3)
    assert.equal(new Set(resumed.map((row) => row.alert_id)).size, resumed.length)
    assert.deepEqual(resumed, await api('alerts?newest=true&limit=200'))
  })
  await test('Engine filter combines with search/class/severity, reset and JSON export', async () => {
    const records = await api('alerts?newest=true&limit=200')
    const chosen = records[0]
    await page.getByLabel('Filter detection engine').selectOption(chosen.detection_source)
    const download = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export JSON', exact: true }).click()
    const filtered = JSON.parse(await readFile(await (await download).path(), 'utf8'))
    assert.deepEqual(
      filtered,
      records.filter((row) => row.detection_source === chosen.detection_source),
    )
    await page.getByLabel('Filter threat class').selectOption(chosen.threat_class)
    await page.getByLabel('Filter severity').selectOption(chosen.severity)
    await page.getByLabel('Search alerts', { exact: true }).fill(chosen.alert_id)
    await until(rows, (count) => count === 1, 'Combined engine filters do not agree')
    await page.getByLabel('Search alerts', { exact: true }).fill('no-such-alert')
    await page.getByRole('heading', { name: 'No matching signals.', exact: true }).waitFor()
    await page.getByRole('button', { name: 'Clear filters', exact: true }).click()
    assert.equal(await page.getByLabel('Filter detection engine').inputValue(), '')
    assert.equal(await page.getByLabel('Filter threat class').inputValue(), '')
    assert.equal(await page.getByLabel('Filter severity').inputValue(), '')
    assert.equal(await page.getByLabel('Search alerts', { exact: true }).inputValue(), '')
    await until(rows, (count) => count === 10, 'Reset did not restore queue')
  })
  await test('Held queue and resume stay bounded at 200 while persistence retains overflow', async () => {
    const before = await api('alerts?limit=1000&newest=true')
    await page.getByRole('button', { name: 'Hold queue', exact: true }).click()
    const added = []
    for (let index = 300; index < 505; index++) added.push(...(await submit(index)))
    assert.equal(added.length, 205)
    await page.getByText('Queue held. 200 newer loaded alerts.', { exact: false }).waitFor()
    const heldDownload = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export JSON', exact: true }).click()
    const held = JSON.parse(await readFile(await (await heldDownload).path(), 'utf8'))
    assert.deepEqual(held, before.slice(0, 200))
    const persisted = await api('alerts?limit=1000&newest=true')
    assert.equal(persisted.length, before.length + 205)
    assert.ok(added.every((row) => persisted.some((item) => item.alert_id === row.alert_id)))
    await page.getByRole('button', { name: 'Resume queue', exact: true }).click()
    const download = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export JSON', exact: true }).click()
    const resumed = JSON.parse(await readFile(await (await download).path(), 'utf8'))
    assert.equal(resumed.length, 200)
    assert.deepEqual(resumed, persisted.slice(0, 200))
    assert.equal(new Set(resumed.map((row) => row.alert_id)).size, 200)
  })
  await test('Investigation controls fit desktop, tablet and phone; reduced motion stays usable', async () => {
    for (const [width, height] of [
      [1440, 1000],
      [768, 1024],
      [390, 844],
      [320, 740],
    ]) {
      await page.setViewportSize({ width, height })
      await layout()
      for (const control of [
        page.getByLabel('Filter detection engine'),
        page.getByRole('button', { name: 'Hold queue', exact: true }),
        page.getByRole('button', { name: 'Export JSON', exact: true }),
      ])
        await bounds(control)
    }
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.getByRole('button', { name: 'Hold queue', exact: true }).click()
    const notice = page.getByText('Queue held. 0 newer loaded alerts.', { exact: false })
    await notice.waitFor()
    const durations = await notice.evaluate((node) =>
      node.parentElement.getAnimations().map((animation) => animation.effect.getTiming().duration),
    )
    assert.ok(
      durations.every((value) => typeof value === 'number' && value <= 1),
      'Reduced motion retained a queue transition',
    )
    await page.screenshot({ path: path.join(output, 'monitor-mobile.png'), fullPage: true })
    await page.getByRole('button', { name: 'Resume queue', exact: true }).click()
    await page.setViewportSize({ width: 1440, height: 1000 })
    await page.screenshot({ path: path.join(output, 'monitor-desktop.png'), fullPage: true })
    await page.setViewportSize({ width: 390, height: 844 })
  })
  await test('Landing/Monitor routing and reduced-motion UI', async () => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.getByRole('banner').getByRole('link', { name: 'Univect home' }).click()
    await page.waitForURL(`${base}/`)
    await page.getByRole('button', { name: 'Open menu', exact: true }).click()
    await page
      .getByRole('navigation', { name: 'Mobile navigation', exact: true })
      .getByRole('link', { name: 'Open monitor', exact: true })
      .click()
    await page.waitForURL(`${base}/monitor`)
    await ready()
    await layout()
  })
  await test('Reduced motion applies on initial load and animations can be re-enabled', async () => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.reload()
    await ready()
    const hold = page.getByRole('button', { name: 'Hold queue', exact: true })
    const resume = page.getByRole('button', { name: 'Resume queue', exact: true })
    const notice = page.getByText('Queue held. 0 newer loaded alerts.', { exact: false })
    const durations = () =>
      notice.evaluate((node) =>
        node.parentElement
          .getAnimations()
          .map((animation) => animation.effect.getTiming().duration),
      )
    await hold.click()
    await notice.waitFor()
    assert.ok((await durations()).every((value) => typeof value === 'number' && value <= 1))
    await resume.click()
    await notice.waitFor({ state: 'hidden' })
    await page.emulateMedia({ reducedMotion: 'no-preference' })
    await hold.click()
    await notice.waitFor()
    assert.ok(
      (await durations()).some((value) => typeof value === 'number' && value > 1),
      'Animations did not resume after preference changed',
    )
    await resume.click()
    await page.emulateMedia({ reducedMotion: 'reduce' })
    // Reveal sections before the full-page artifact; anchor the sticky nav at top.
    await page.locator('#coverage').scrollIntoViewIfNeeded()
    await page.locator('footer').scrollIntoViewIfNeeded()
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }))
    await page.setViewportSize({ width: 1440, height: 1000 })
    await page.screenshot({ path: path.join(output, 'monitor-desktop-final.png'), fullPage: true })
    await page
      .locator('#alerts')
      .screenshot({ path: path.join(output, 'investigation-desktop.png') })
    await page.setViewportSize({ width: 390, height: 844 })
    await hold.click()
    await page
      .locator('#alerts')
      .screenshot({ path: path.join(output, 'investigation-mobile.png') })
    await resume.click()
  })
  await test('Browser runtime and console', async () => assert.deepEqual(errors, []))
} finally {
  const report = {
    base,
    browser: browser.version(),
    checked_at: new Date().toISOString(),
    passed: results.filter((result) => result.passed).length,
    total: results.length,
    results,
    errors,
  }
  await writeFile(path.join(output, 'results.json'), JSON.stringify(report, null, 2) + '\n')
  await context.close()
  await browser.close()
  if (report.passed !== report.total) process.exitCode = 1
  console.log(`${report.passed}/${report.total} checks passed. Report: ${output}`)
}
