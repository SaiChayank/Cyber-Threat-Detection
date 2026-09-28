import './style.css'

type Alert = { sequence: number; timestamp: number; flow_id: string; alert_id: string; threat_class: string; severity: string; confidence_score: number; supporting_evidence: string; src_ip: string; dst_ip: string; src_port: number; dst_port: number; detection_source: string; raw_evidence_metrics: Record<string, unknown> }
type Telemetry = { processed: number; processing_p95_ms: number; active_sources: number; late_events: number; state_evictions: number; replay_status: string; replay_error: string | null; alerts_by_class: Record<string, number> }
const classes = ['DDOS', 'BOTNET_C2', 'DGA_DOMAINS', 'DNS_TUNNELLING', 'ENCRYPTED_MALWARE', 'RECONNAISSANCE', 'DATA_EXFILTRATION']
const names: Record<string, string> = { DDOS: 'DDoS', BOTNET_C2: 'C2 beaconing', DGA_DOMAINS: 'DGA domains', DNS_TUNNELLING: 'DNS tunnelling', ENCRYPTED_MALWARE: 'Encrypted malware', RECONNAISSANCE: 'Reconnaissance', DATA_EXFILTRATION: 'Data exfiltration', BENIGN: 'Benign baseline' }
const api = location.port === '5173' ? 'http://127.0.0.1:8000' : ''
let records: Alert[] = []
let filter = ''
let selected: Alert | undefined
let cursor = 0
let source: EventSource | undefined
let backendUnavailable = false
let lastProcessed = 0
let lastSampleAt = 0
let trafficSamples: number[] = []
const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T
const safe = (value: unknown) => String(value ?? 'Unavailable').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!))

el('app').innerHTML = `
  <aside><a class="brand" href="#top"><span class="brand-icon">◈</span><span>SENTINEL<small>PS26145 · NTRO</small></span></a><div class="nav-label">MONITORING</div><a class="nav active" href="#top"><span>◉</span> Overview</a><a class="nav" href="#replay"><span>▷</span> Traffic replay</a><a class="nav" href="#coverage"><span>⌁</span> Detection coverage</a><a class="nav" href="#alerts"><span>≋</span> Alert stream</a><div class="nav-label resources-label">RESOURCES</div><a class="nav" href="${api}/docs" target="_blank" rel="noopener"><span>↗</span> API reference</a><div class="aside-bottom"><span class="dot"></span><b>Passive sensor</b><small>Read-only ingest<br>Metadata only · No response path</small></div></aside>
  <main id="top"><header><div><div class="eyebrow">NETWORK INTELLIGENCE <span class="eyebrow-divider">/</span> OPERATIONS CENTER</div><h1>Threat monitor</h1><p>Live visibility across passively observed network traffic.</p></div><div class="connection"><span class="dot" id="connection-dot"></span><span id="connection">Connecting</span><span class="connection-divider"></span><span class="connection-label">SENSOR A-01</span></div></header>
  <div class="notice"><span class="notice-icon">◈</span><div><b>PASSIVE MODE</b><span>One-way observation · Encrypted content stays opaque · Alerts never trigger network actions</span></div><span class="notice-tag">LAB PROTOTYPE</span></div>
  <section class="metrics"><article class="metric-card"><div class="metric-heading"><span>EVENTS PROCESSED</span><span class="metric-icon">⌁</span></div><strong id="processed">0</strong><small>Incremental flow inference</small></article><article class="metric-card"><div class="metric-heading"><span>ALERTS RECORDED</span><span class="metric-icon alert-icon">!</span></div><strong id="alert-count">0</strong><small>Evidence-backed detections</small></article><article class="metric-card"><div class="metric-heading"><span>PROCESSING P95</span><span class="metric-icon">◷</span></div><strong id="latency">0 <em>ms</em></strong><small>Feature extraction + inference</small></article><article class="metric-card"><div class="metric-heading"><span>REPLAY STATE</span><span class="state-pill"><i></i><span id="replay-status">Idle</span></span></div><strong id="throughput">0 <em>flows/s</em></strong><small id="state-detail">Waiting for traffic</small></article></section>
  <section class="overview-grid"><article class="panel traffic-panel"><div class="panel-heading"><div><div class="eyebrow">INGEST TELEMETRY</div><h2>Observed flow rate</h2><p>Recent event processing rate · sampled locally</p></div><div class="traffic-current"><strong id="rate-current">0</strong><span>flows / sec</span></div></div><div class="chart-wrap"><div class="chart-axis"><span>ACTIVE</span><span>EVENT RATE</span></div><svg id="traffic-chart" viewBox="0 0 700 150" preserveAspectRatio="none" role="img" aria-label="Recent observed flow rate"><defs><linearGradient id="traffic-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#54e0c0" stop-opacity=".22"/><stop offset="100%" stop-color="#54e0c0" stop-opacity="0"/></linearGradient></defs><path id="traffic-area" d="M0 142 L700 142 L700 150 L0 150 Z" fill="url(#traffic-fill)"/><path id="traffic-line" d="M0 142 L700 142" fill="none" stroke="#54e0c0" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg><div class="chart-times"><span>24 samples</span><span>Now</span></div></div></article><article class="panel integrity-panel"><div class="eyebrow">COLLECTION BOUNDARY</div><h2>One-way by design</h2><p>The sensor observes mirrored traffic and emits intelligence to this dashboard only.</p><div class="boundary-flow"><div><span class="boundary-node">⇢</span><b>Mirror feed</b><small>Read only</small></div><span class="boundary-line"></span><div><span class="boundary-node sensor-node">◈</span><b>Analytics enclave</b><small>Metadata only</small></div><span class="boundary-block">×</span></div><div class="integrity-foot"><span><i></i> No path to source</span><span><i></i> No payload decryption</span></div></article></section>
  <section class="panel replay" id="replay"><div class="replay-copy"><div class="eyebrow">CONTROLLED TESTING</div><h2>Traffic replay</h2><p>Run a scenario or inspect a passive capture.</p></div><div class="controls"><select id="scenario" aria-label="Scenario"><option value="ALL">All threat scenarios</option><option value="BENIGN">Benign baseline</option>${classes.map(c => `<option value="${c}">${names[c]}</option>`).join('')}</select><select id="speed" aria-label="Replay speed"><option value="1">1× speed</option><option value="20">20× speed</option><option value="100" selected>100× speed</option><option value="1000">1000× speed</option></select><button id="start" class="primary"><span>▶</span> Start replay</button><button id="stop">Stop</button><label class="upload"><span>↑</span> PCAP<input id="pcap" type="file" accept=".pcap" /></label></div></section>
  <p id="message" role="status"></p>
  <section class="coverage" id="coverage"><div class="section-title"><div><div class="eyebrow">DETECTION ENGINES</div><h2>Threat coverage</h2></div><span>Six required threat categories · Counts from recorded alerts</span></div><div id="coverage-cards">${classes.map(c => `<article><span class="module-dot"></span><span>${names[c]}</span><strong id="count-${c}">0</strong></article>`).join('')}</div></section>
  <section class="panel feed" id="alerts"><div class="feed-header"><div><div class="eyebrow">INVESTIGATION QUEUE</div><h2>Alert stream <span class="live-tag">LIVE</span></h2><p>Select an alert to inspect the observed evidence.</p></div><div class="feed-actions"><select id="filter" aria-label="Filter threat class"><option value="">All threats</option>${classes.map(c => `<option value="${c}">${names[c]}</option>`).join('')}</select><button id="export">↓ &nbsp; Export JSON</button></div></div><div class="table-wrap"><table><thead><tr><th>OBSERVED TIME</th><th>THREAT</th><th>SOURCE → DESTINATION</th><th>SEVERITY</th><th>CONFIDENCE</th><th>ENGINE</th></tr></thead><tbody id="rows"></tbody></table></div><div class="feed-footer">Latest 200 records · Newest first <span id="dropped">0 late events</span></div></section>
  <footer><span>PS26145 · Passive network threat intelligence</span><span>One-way observation <b>·</b> No inline blocking <b>·</b> No payload decryption</span></footer></main>
  <dialog id="detail"><div class="detail-header"><div><div class="eyebrow">ALERT INVESTIGATION</div><h2 id="detail-title"></h2></div><button id="close" aria-label="Close alert detail">✕</button></div><div id="detail-content"></div></dialog>`

async function request(path: string, options?: RequestInit) {
  const response = await fetch(api + path, options)
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(typeof body.detail === 'string' ? body.detail : `Request failed (${response.status})`)
  }
  return response.json()
}
function message(text: string, error = false) { el('message').textContent = text; el('message').className = error ? 'error' : '' }
function render() {
  const visible = records.filter(a => !filter || a.threat_class === filter)
  el('rows').innerHTML = visible.length ? visible.map(a => `<tr tabindex="0" data-sequence="${a.sequence}" aria-label="Inspect ${safe(names[a.threat_class])} alert"><td>${safe(new Date(a.timestamp).toISOString().slice(11, 23))}<small>${safe(new Date(a.timestamp).toISOString().slice(0, 10))}</small></td><td><b>${safe(names[a.threat_class] || a.threat_class)}</b></td><td class="address">${safe(a.src_ip)}<span>→ ${safe(a.dst_ip)}</span></td><td><span class="badge ${safe(a.severity.toLowerCase())}">${safe(a.severity)}</span></td><td><div class="confidence"><span>${(a.confidence_score * 100).toFixed(1)}%</span><i style="width:${Math.max(0, Math.min(100, a.confidence_score * 100))}%"></i></div></td><td><span class="engine">${safe(a.detection_source)}</span></td></tr>`).join('') : '<tr><td colspan="6" class="empty"><span>◈</span><h3>Ready to observe</h3><p>Start a replay to see threats, confidence scores, and evidence here.</p></td></tr>'
  el('rows').querySelectorAll<HTMLTableRowElement>('tr[data-sequence]').forEach(row => {
    const open = () => { selected = records.find(a => a.sequence === Number(row.dataset.sequence)); if (selected) showDetail(selected) }
    row.onclick = open
    row.onkeydown = event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open() } }
  })
}
function showDetail(a: Alert) {
  el('detail-title').textContent = names[a.threat_class] || a.threat_class
  el('detail-content').innerHTML = `<div class="detail-summary"><span class="badge ${safe(a.severity.toLowerCase())}">${safe(a.severity)}</span><b>${(a.confidence_score * 100).toFixed(1)}% confidence</b><span>${safe(a.detection_source)}</span></div><h3>Observed connection</h3><p class="address">${safe(a.src_ip)}:${a.src_port} → ${safe(a.dst_ip)}:${a.dst_port}</p><p>${safe(new Date(a.timestamp).toISOString())}</p><h3>Supporting evidence</h3><p class="evidence-text">${safe(a.supporting_evidence)}</p><div class="evidence-grid">${Object.entries(a.raw_evidence_metrics || {}).map(([k, v]) => `<div><span>${safe(k.replaceAll('_', ' '))}</span><b>${safe(typeof v === 'number' ? Number(v.toFixed(4)) : v)}</b></div>`).join('')}</div><h3>Identifiers</h3><p class="identifier">Flow: ${safe(a.flow_id)}<br>Alert: ${safe(a.alert_id)}</p><p class="detail-note">An alert is evidence of suspicious behavior, not confirmation of compromise. Encrypted content remains opaque.</p>`
  el<HTMLDialogElement>('detail').showModal()
}
function connect() {
  source?.close()
  source = new EventSource(`${api}/api/stream?after=${cursor}`)
  source.onopen = () => { el('connection').textContent = 'Stream connected'; el('connection-dot').classList.remove('offline') }
  source.onerror = () => { el('connection').textContent = 'Reconnecting'; el('connection-dot').classList.add('offline') }
  source.onmessage = event => {
    const a = JSON.parse(event.data) as Alert
    cursor = Math.max(cursor, a.sequence)
    if (!records.some(r => r.sequence === a.sequence)) { records.unshift(a); records = records.slice(0, 200); render() }
  }
}
function updateTraffic(processed: number) {
  const now = Date.now()
  const rate = lastSampleAt ? Math.max(0, (processed - lastProcessed) / ((now - lastSampleAt) / 1000)) : 0
  trafficSamples.push(rate)
  trafficSamples = trafficSamples.slice(-24)
  lastProcessed = processed
  lastSampleAt = now
  const shown = Math.round(rate).toLocaleString()
  el('throughput').innerHTML = `${shown} <em>flows/s</em>`
  el('rate-current').textContent = shown
  const max = Math.max(1, ...trafficSamples)
  const points = trafficSamples.map((value, index) => {
    const x = (index + 24 - trafficSamples.length) / 23 * 700
    const y = 142 - value / max * 112
    return `${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' L')
  const start = trafficSamples.length < 2 ? '700 142' : points;
  document.querySelector<SVGPathElement>('#traffic-line')!.setAttribute('d', `M${start}`)
  const firstX = (24 - trafficSamples.length) / 23 * 700;
  document.querySelector<SVGPathElement>('#traffic-area')!.setAttribute('d', `M${start} L700 150 L${firstX.toFixed(1)} 150 Z`)
}
async function refresh() {
  try {
    const t = await request('/api/telemetry') as Telemetry
    updateTraffic(t.processed)
    el('processed').textContent = t.processed.toLocaleString()
    el('latency').innerHTML = `${t.processing_p95_ms.toFixed(2)} <em>ms</em>`
    el('replay-status').textContent = t.replay_status
    el('state-detail').textContent = `${t.active_sources} active sources · ${t.state_evictions} state evictions`
    el('alert-count').textContent = Object.values(t.alerts_by_class).reduce((a, b) => a + b, 0).toLocaleString()
    classes.forEach(c => { el(`count-${c}`).textContent = String(t.alerts_by_class[c] || 0) })
    el('dropped').textContent = `${t.late_events} late events dropped`
    el<HTMLButtonElement>('start').disabled = t.replay_status === 'running'
    if (backendUnavailable) { backendUnavailable = false; message('') }
    if (t.replay_error) message(t.replay_error, true)
  } catch { backendUnavailable = true; message('Backend unavailable. Start the local API on port 8000.', true) }
}
el('start').onclick = async () => {
  try { await request('/api/replay/start', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario: el<HTMLSelectElement>('scenario').value, speed: Number(el<HTMLSelectElement>('speed').value) }) }); message('Replay started. Alerts are emitted while events arrive.'); await refresh() } catch (e) { message(String(e), true) }
}
el('stop').onclick = async () => { try { await request('/api/replay/stop', { method: 'POST' }); message('Replay stopped. Recorded alerts are preserved.'); await refresh() } catch (e) { message(String(e), true) } }
el<HTMLSelectElement>('filter').onchange = () => { filter = el<HTMLSelectElement>('filter').value; render() }
el('close').onclick = () => el<HTMLDialogElement>('detail').close()
el('export').onclick = () => {
  const blob = new Blob([JSON.stringify(records.filter(a => !filter || a.threat_class === filter), null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = 'sentinel-alerts.json'; link.click(); URL.revokeObjectURL(url)
}
el<HTMLInputElement>('pcap').onchange = async event => {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  if (file.size > 16 * 1024 * 1024) { message('PCAP limit is 16 MiB.', true); return }
  try { await request(`/api/replay/pcap?speed=${el<HTMLSelectElement>('speed').value}`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file }); message('PCAP replay started. Only captured metadata is analyzed.') } catch (e) { message(String(e), true) }
  input.value = ''
}
async function init() {
  render()
  try {
    const datasets = await request('/api/datasets') as { id: string; name: string; ready: boolean }[]
    for (const dataset of datasets.filter(d => d.ready)) {
      const option = document.createElement('option'); option.value = dataset.id; option.textContent = dataset.name
      el<HTMLSelectElement>('scenario').append(option)
    }
  } catch { /* Dataset presets are optional until downloads are prepared. */ }
  try { records = await request('/api/alerts?newest=true&limit=200'); cursor = records[0]?.sequence || 0; render() } catch { backendUnavailable = true; message('Waiting for backend connection.', true) }
  connect(); await refresh()
}
void init()
setInterval(() => void refresh(), 1500)
window.addEventListener('beforeunload', () => source?.close())
