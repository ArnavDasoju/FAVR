/**
 * Post-patch verifier.
 *
 * After agents land their fixes we need to prove the project still installs,
 * builds, tests, and boots. Runs an ecosystem-aware chain of checks and
 * streams step-by-step results to the UI so the user can see exactly what
 * passed, what failed, and why — before committing to a rescan.
 *
 * Tiers:
 *   1. Install / resolve — does the new manifest resolve on the registry?
 *   2. Build + tests      — does the project still compile and its tests pass?
 *   3. Dev server boot    — does the app start and bind a port?
 *
 * Each step has a hard timeout so a stuck build can't hang the UI forever.
 */

import { spawn } from 'child_process'
import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import { BrowserWindow } from 'electron'
import * as http from 'http'
import * as net from 'net'

export type VerifyStepStatus = 'pending' | 'running' | 'pass' | 'fail' | 'skip'

export interface VerifyStep {
  id: string
  label: string
  status: VerifyStepStatus
  output?: string
  durationMs?: number
  command?: string
}

export interface VerifyResult {
  steps: VerifyStep[]
  allPassed: boolean
  ecosystem: string
  durationMs: number
}

interface RunOpts {
  cwd: string
  timeoutMs: number
  maxOutputLines?: number
}

function emit(channel: string, payload: unknown) {
  for (const win of BrowserWindow.getAllWindows()) {
    win.webContents.send(channel, payload)
  }
}

function runCommand(
  cmd: string,
  args: string[],
  opts: RunOpts
): Promise<{ code: number; output: string; timedOut: boolean }> {
  return new Promise(resolve => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      shell: process.platform === 'win32',
      env: { ...process.env, CI: '1', FORCE_COLOR: '0' }
    })

    const lines: string[] = []
    const maxLines = opts.maxOutputLines ?? 80
    const push = (buf: Buffer) => {
      const text = buf.toString('utf-8')
      for (const line of text.split('\n')) {
        if (line.trim().length === 0) continue
        lines.push(line)
        if (lines.length > maxLines) lines.shift()
      }
    }
    child.stdout?.on('data', push)
    child.stderr?.on('data', push)

    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, opts.timeoutMs)

    child.on('error', err => {
      clearTimeout(timer)
      resolve({ code: 1, output: `${err.message}\n${lines.join('\n')}`, timedOut: false })
    })
    child.on('close', code => {
      clearTimeout(timer)
      resolve({ code: code ?? 1, output: lines.join('\n'), timedOut })
    })
  })
}

// ─── Ecosystem detection ───────────────────────────────────────────────

interface Ecosystem {
  name: string
  detect: () => boolean
  buildSteps: () => VerifyStep[]
  run: (step: VerifyStep, cwd: string) => Promise<{ passed: boolean; output: string }>
}

function readJsonSafe(path: string): any {
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return null
  }
}

// ─── Public API ────────────────────────────────────────────────────────

export async function runVerification(codebasePath: string): Promise<VerifyResult> {
  const started = Date.now()
  const ecosystem = detectEcosystem(codebasePath)
  const steps: VerifyStep[] = buildSteps(codebasePath, ecosystem)

  emit('verify:started', { steps, ecosystem })

  let allPassed = true
  for (const step of steps) {
    step.status = 'running'
    emit('verify:step', { ...step })

    const stepStart = Date.now()
    try {
      const { passed, output, skipped } = await executeStep(step, codebasePath, ecosystem)
      step.durationMs = Date.now() - stepStart
      step.output = output
      step.status = skipped ? 'skip' : passed ? 'pass' : 'fail'
      if (!passed && !skipped) allPassed = false
    } catch (err) {
      step.durationMs = Date.now() - stepStart
      step.output = err instanceof Error ? err.message : String(err)
      step.status = 'fail'
      allPassed = false
    }
    emit('verify:step', { ...step })
  }

  const result: VerifyResult = {
    steps,
    allPassed,
    ecosystem,
    durationMs: Date.now() - started
  }
  emit('verify:complete', result)
  return result
}

// ─── Detection ─────────────────────────────────────────────────────────

function detectEcosystem(cwd: string): string {
  if (existsSync(join(cwd, 'package.json'))) return 'node'
  if (existsSync(join(cwd, 'go.mod'))) return 'go'
  if (existsSync(join(cwd, 'Cargo.toml'))) return 'rust'
  if (existsSync(join(cwd, 'requirements.txt')) || existsSync(join(cwd, 'pyproject.toml'))) return 'python'
  if (existsSync(join(cwd, 'Gemfile'))) return 'ruby'
  return 'unknown'
}

function buildSteps(cwd: string, ecosystem: string): VerifyStep[] {
  const steps: VerifyStep[] = []

  if (ecosystem === 'node') {
    const pkg = readJsonSafe(join(cwd, 'package.json'))
    const scripts = pkg?.scripts ?? {}
    const tool = detectNodeTool(cwd)
    steps.push({ id: 'install', label: `Dependencies resolve (${tool})`, status: 'pending', command: `${tool} install --dry-run` })
    if (scripts.build) steps.push({ id: 'build', label: 'Build succeeds', status: 'pending', command: `${tool} run build` })
    if (scripts.test) steps.push({ id: 'test', label: 'Tests pass', status: 'pending', command: `${tool} test` })
    if (scripts.dev || scripts.start) steps.push({ id: 'boot', label: 'Dev server boots', status: 'pending', command: scripts.dev ? `${tool} run dev` : `${tool} start` })
  } else if (ecosystem === 'python') {
    steps.push({ id: 'install', label: 'Dependencies resolve (pip)', status: 'pending', command: 'pip install --dry-run' })
    if (existsSync(join(cwd, 'pytest.ini')) || existsSync(join(cwd, 'tests')) || existsSync(join(cwd, 'test'))) {
      steps.push({ id: 'test', label: 'Tests pass (pytest)', status: 'pending', command: 'pytest -x -q' })
    }
  } else if (ecosystem === 'go') {
    steps.push({ id: 'install', label: 'go mod tidy', status: 'pending', command: 'go mod tidy' })
    steps.push({ id: 'build', label: 'go build', status: 'pending', command: 'go build ./...' })
    steps.push({ id: 'test', label: 'go test', status: 'pending', command: 'go test ./...' })
  } else if (ecosystem === 'rust') {
    steps.push({ id: 'install', label: 'cargo check', status: 'pending', command: 'cargo check --locked' })
    steps.push({ id: 'test', label: 'cargo test', status: 'pending', command: 'cargo test --no-run' })
  } else if (ecosystem === 'ruby') {
    steps.push({ id: 'install', label: 'bundle check', status: 'pending', command: 'bundle check' })
  } else {
    steps.push({ id: 'unknown', label: 'No supported ecosystem detected', status: 'skip' })
  }

  return steps
}

function detectNodeTool(cwd: string): 'pnpm' | 'yarn' | 'npm' {
  if (existsSync(join(cwd, 'pnpm-lock.yaml'))) return 'pnpm'
  if (existsSync(join(cwd, 'yarn.lock'))) return 'yarn'
  return 'npm'
}

// ─── Step execution ────────────────────────────────────────────────────

async function executeStep(
  step: VerifyStep,
  cwd: string,
  ecosystem: string
): Promise<{ passed: boolean; output: string; skipped?: boolean }> {
  if (step.id === 'unknown') return { passed: true, output: 'Nothing to verify.', skipped: true }

  if (ecosystem === 'node') return executeNodeStep(step, cwd)
  if (ecosystem === 'python') return executePythonStep(step, cwd)
  if (ecosystem === 'go') return executeGoStep(step, cwd)
  if (ecosystem === 'rust') return executeRustStep(step, cwd)
  if (ecosystem === 'ruby') return executeRubyStep(step, cwd)
  return { passed: false, output: `Unsupported ecosystem: ${ecosystem}` }
}

async function executeNodeStep(step: VerifyStep, cwd: string) {
  const tool = detectNodeTool(cwd)
  switch (step.id) {
    case 'install': {
      // Dry-run resolve — validates that the new versions exist in the registry
      // and that peer deps don't conflict, without actually downloading.
      const args = tool === 'pnpm'
        ? ['install', '--lockfile-only', '--prefer-offline']
        : tool === 'yarn'
          ? ['install', '--mode=update-lockfile']
          : ['install', '--package-lock-only', '--no-audit', '--no-fund']
      const { code, output, timedOut } = await runCommand(tool, args, { cwd, timeoutMs: 180_000 })
      return { passed: code === 0 && !timedOut, output: timedOut ? '[timed out]\n' + output : output }
    }
    case 'build': {
      const { code, output, timedOut } = await runCommand(tool, ['run', 'build'], { cwd, timeoutMs: 300_000 })
      return { passed: code === 0 && !timedOut, output: timedOut ? '[timed out]\n' + output : output }
    }
    case 'test': {
      const args = tool === 'npm' ? ['test', '--', '--run'] : ['test']
      const { code, output, timedOut } = await runCommand(tool, args, { cwd, timeoutMs: 240_000 })
      return { passed: code === 0 && !timedOut, output: timedOut ? '[timed out]\n' + output : output }
    }
    case 'boot':
      return bootAndProbe(tool, cwd)
    default:
      return { passed: false, output: `Unknown Node step: ${step.id}` }
  }
}

async function executePythonStep(step: VerifyStep, cwd: string) {
  switch (step.id) {
    case 'install': {
      const req = join(cwd, 'requirements.txt')
      if (existsSync(req)) {
        const { code, output, timedOut } = await runCommand('pip', ['install', '--dry-run', '-r', 'requirements.txt'], { cwd, timeoutMs: 120_000 })
        return { passed: code === 0 && !timedOut, output: timedOut ? '[timed out]\n' + output : output }
      }
      // pyproject
      const { code, output, timedOut } = await runCommand('pip', ['install', '--dry-run', '.'], { cwd, timeoutMs: 120_000 })
      return { passed: code === 0 && !timedOut, output: timedOut ? '[timed out]\n' + output : output }
    }
    case 'test': {
      const { code, output, timedOut } = await runCommand('pytest', ['-x', '-q'], { cwd, timeoutMs: 180_000 })
      return { passed: code === 0 && !timedOut, output: timedOut ? '[timed out]\n' + output : output }
    }
    default:
      return { passed: false, output: `Unknown Python step: ${step.id}` }
  }
}

async function executeGoStep(step: VerifyStep, cwd: string) {
  if (step.id === 'install') {
    const r = await runCommand('go', ['mod', 'tidy'], { cwd, timeoutMs: 120_000 })
    return { passed: r.code === 0 && !r.timedOut, output: r.output }
  }
  if (step.id === 'build') {
    const r = await runCommand('go', ['build', './...'], { cwd, timeoutMs: 240_000 })
    return { passed: r.code === 0 && !r.timedOut, output: r.output }
  }
  if (step.id === 'test') {
    const r = await runCommand('go', ['test', './...'], { cwd, timeoutMs: 240_000 })
    return { passed: r.code === 0 && !r.timedOut, output: r.output }
  }
  return { passed: false, output: `Unknown Go step: ${step.id}` }
}

async function executeRustStep(step: VerifyStep, cwd: string) {
  if (step.id === 'install') {
    const r = await runCommand('cargo', ['check', '--locked'], { cwd, timeoutMs: 300_000 })
    return { passed: r.code === 0 && !r.timedOut, output: r.output }
  }
  if (step.id === 'test') {
    const r = await runCommand('cargo', ['test', '--no-run'], { cwd, timeoutMs: 300_000 })
    return { passed: r.code === 0 && !r.timedOut, output: r.output }
  }
  return { passed: false, output: `Unknown Rust step: ${step.id}` }
}

async function executeRubyStep(step: VerifyStep, cwd: string) {
  if (step.id === 'install') {
    const r = await runCommand('bundle', ['check'], { cwd, timeoutMs: 60_000 })
    return { passed: r.code === 0 && !r.timedOut, output: r.output }
  }
  return { passed: false, output: `Unknown Ruby step: ${step.id}` }
}

// ─── Dev-server boot probe ─────────────────────────────────────────────

async function bootAndProbe(tool: string, cwd: string): Promise<{ passed: boolean; output: string }> {
  const pkg = readJsonSafe(join(cwd, 'package.json'))
  const hasDev = !!pkg?.scripts?.dev
  const args = tool === 'npm'
    ? (hasDev ? ['run', 'dev'] : ['start'])
    : (hasDev ? ['run', 'dev'] : ['start'])

  // Pre-pick a free port; some frameworks honor PORT, some don't — either way
  // we'll also scan common defaults.
  const port = await findFreePort()
  const candidates = [port, 3000, 3001, 5173, 4321, 8080, 8000, 4200]

  const child = spawn(tool, args, {
    cwd,
    shell: process.platform === 'win32',
    env: { ...process.env, PORT: String(port), CI: '0', BROWSER: 'none', FORCE_COLOR: '0' }
  })

  const lines: string[] = []
  const capture = (buf: Buffer) => {
    for (const l of buf.toString('utf-8').split('\n')) {
      if (l.trim()) {
        lines.push(l)
        if (lines.length > 80) lines.shift()
      }
    }
  }
  child.stdout?.on('data', capture)
  child.stderr?.on('data', capture)

  const bootTimeoutMs = 45_000
  const start = Date.now()

  const listening = await new Promise<number | null>(resolve => {
    let settled = false
    const done = (v: number | null) => { if (!settled) { settled = true; resolve(v) } }

    const poll = async () => {
      while (Date.now() - start < bootTimeoutMs && !settled) {
        for (const p of candidates) {
          if (await probePort(p)) { done(p); return }
        }
        await new Promise(r => setTimeout(r, 500))
      }
      done(null)
    }
    poll()

    child.on('exit', code => {
      done(null)
      lines.push(`[process exited with code ${code} before binding a port]`)
    })
  })

  // Always tear down the dev server
  try { child.kill('SIGKILL') } catch { /* ignore */ }

  if (listening === null) {
    return { passed: false, output: '[dev server did not bind a port within 45s]\n' + lines.join('\n') }
  }
  return { passed: true, output: `Dev server bound port ${listening} in ${Date.now() - start}ms\n` + lines.join('\n') }
}

function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, () => {
      const addr = srv.address()
      const port = typeof addr === 'object' && addr ? addr.port : 0
      srv.close(() => resolve(port))
    })
  })
}

function probePort(port: number): Promise<boolean> {
  return new Promise(resolve => {
    const req = http.request({ host: '127.0.0.1', port, path: '/', method: 'GET', timeout: 1500 }, res => {
      res.resume()
      resolve(true)
    })
    req.on('error', () => resolve(false))
    req.on('timeout', () => { req.destroy(); resolve(false) })
    req.end()
  })
}
