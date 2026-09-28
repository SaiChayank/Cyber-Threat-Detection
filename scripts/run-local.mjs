import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { createServer } from 'node:net'
import { ensurePython } from './setup-python.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
if (existsSync(path.join(root, '.env'))) process.loadEnvFile(path.join(root, '.env'))
const mode = ['start', 'build'].includes(process.argv[2]) ? process.argv[2] : 'dev'
const host = process.env.API_HOST || '127.0.0.1'
const apiPort = process.env.API_PORT || '8000'
const api = process.env.API_PROXY_URL || `http://${host}:${apiPort}`
let port = Number(process.env.WEB_PORT || 3000)
const children = new Set()
let stopping = false

function shutdown(code = 0) {
  if (stopping) return
  stopping = true
  for (const child of children) {
    if (process.platform === 'win32' && child.pid)
      spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
      })
    else child.kill('SIGTERM')
  }
  process.exitCode = code
}

function launch(command, args, options = {}) {
  const child = spawn(command, args, { cwd: root, stdio: 'inherit', ...options })
  children.add(child)
  child.on('error', (error) => {
    console.error(error.message)
    shutdown(1)
  })
  child.on('exit', (code) => {
    children.delete(child)
    if (!stopping) shutdown(code || 0)
  })
  return child
}

async function ready() {
  try {
    const response = await fetch(`${api}/api/health`, { signal: AbortSignal.timeout(1500) })
    const body = await response.json()
    return response.ok && body.architecture === 'unidirectional-passive-monitoring'
  } catch {
    return false
  }
}

process.on('SIGINT', () => shutdown())
process.on('SIGTERM', () => shutdown())

async function addressAvailable(candidate, address) {
  return new Promise((resolve) => {
    const probe = createServer()
    probe.once('error', (error) => resolve(address === '::' && error.code === 'EAFNOSUPPORT'))
    probe.listen(candidate, address, () => probe.close(() => resolve(true)))
  })
}
async function portAvailable(candidate) {
  return (
    (await addressAvailable(candidate, '127.0.0.1')) && (await addressAvailable(candidate, '::'))
  )
}

if (mode !== 'build') {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('WEB_PORT must be an integer from 1 to 65535.')
    process.exit(1)
  }
  if (process.env.WEB_PORT && !(await portAvailable(port))) {
    console.error(`Port ${port} is in use. Set WEB_PORT to a free port in .env.`)
    process.exit(1)
  }
  if (!process.env.WEB_PORT) {
    while (port <= 3010 && !(await portAvailable(port))) port++
    if (port > 3010) {
      console.error('No free port from 3000 to 3010. Set WEB_PORT in .env.')
      process.exit(1)
    }
    if (port !== 3000) console.log(`Port 3000 is in use; using ${port}.`)
  }
  process.env.WEB_PORT = String(port)
}

if (mode === 'build') {
  const require = createRequire(path.join(root, 'frontend', 'package.json'))
  launch(process.execPath, [require.resolve('next/dist/bin/next'), 'build'], {
    cwd: path.join(root, 'frontend'),
    env: process.env,
  })
} else if (await ready()) {
  console.log(`Using the running Univect API at ${api}`)
} else {
  if (api !== `http://${host}:${apiPort}`) {
    console.error(`The configured API is unavailable: ${api}`)
    process.exit(1)
  }
  let python
  try {
    python = await ensurePython(root)
  } catch (error) {
    console.error(error.message)
    process.exit(1)
  }
  launch(python, ['-m', 'uvicorn', 'backend.main:app', '--host', host, '--port', apiPort])
  let available = false
  for (let attempt = 0; attempt < 40 && !stopping; attempt++) {
    if (await ready()) {
      available = true
      break
    }
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  if (!available) {
    console.error('API failed to start. Check the Python output above.')
    shutdown(1)
  }
}

if (!stopping && mode !== 'build') {
  const require = createRequire(path.join(root, 'frontend', 'package.json'))
  console.log(`Univect: http://localhost:${port}`)
  launch(
    process.execPath,
    [require.resolve('next/dist/bin/next'), mode, '-p', String(port), '-H', '127.0.0.1'],
    {
      cwd: path.join(root, 'frontend'),
      env: { ...process.env, API_PROXY_URL: api },
    },
  )
}
