import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'

function run(command, args, root, quiet = false) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: root,
      stdio: quiet ? 'ignore' : 'inherit',
      windowsHide: true,
    })
    child.on('error', () => resolve(false))
    child.on('exit', (code) => resolve(code === 0))
  })
}

export async function ensurePython(root) {
  const python =
    process.env.PYTHON_EXECUTABLE ||
    path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
  if (!existsSync(python)) {
    if (process.env.PYTHON_EXECUTABLE)
      throw new Error('PYTHON_EXECUTABLE does not exist. Check .env.')
    const candidates =
      process.platform === 'win32' ? [['py', '-3'], ['python']] : [['python3'], ['python']]
    let selected
    for (const candidate of candidates) {
      if (
        await run(
          candidate[0],
          [...candidate.slice(1), '-c', 'import sys; assert sys.version_info >= (3, 11)'],
          root,
          true,
        )
      ) {
        selected = candidate
        break
      }
    }
    if (!selected)
      throw new Error('Install Python 3.11+ and add it to PATH, then run npm run dev again.')
    console.log('Creating the local Python virtual environment…')
    if (!(await run(selected[0], [...selected.slice(1), '-m', 'venv', '.venv'], root)))
      throw new Error('Unable to create .venv. See the Python output above.')
  }
  if (!(await run(python, ['-c', 'import sys; assert sys.version_info >= (3, 11)'], root, true)))
    throw new Error('The selected Python environment requires Python 3.11+. See README.md.')
  const imports = 'import fastapi, uvicorn, pydantic, httpx'
  if (!(await run(python, ['-c', imports], root, true))) {
    console.log('Installing the backend requirements into the selected Python environment…')
    if (!(await run(python, ['-m', 'pip', 'install', '-r', 'requirements.txt'], root)))
      throw new Error('Python dependency installation failed. See README.md for manual setup.')
  }
  return python
}
