/**
 * Error Context Collector — gathers detailed diagnostic info when a task fails.
 * This is fed back to the agent so it can self-correct (the "self-healing" loop).
 */

import { execSync } from 'child_process'

export interface ErrorContext {
  screenshot: string | null        // base64 of the broken output
  apiResponse: string | null       // full HTTP response body
  testOutput: string | null        // test runner stdout/stderr
  consoleOutput: string | null     // agent's terminal output
  stackTrace: string | null        // extracted stack trace
  diff: string | null              // git diff of changes
  vlmAnalysis: string | null       // VLM's description of what's wrong
  originalPrompt: string           // the subtask prompt
}

/**
 * Collect git diff from the project directory.
 */
export function collectGitDiff(projectDir: string): string | null {
  try {
    const diff = execSync('git diff', { cwd: projectDir, encoding: 'utf-8', timeout: 10000 })
    return diff.trim() || null
  } catch {
    return null
  }
}

/**
 * Run tests and capture output.
 */
export function collectTestOutput(projectDir: string): string | null {
  // Try common test commands
  const testCommands = [
    'npm test -- --watchAll=false 2>&1',
    'npx vitest run 2>&1',
    'npx jest --no-coverage 2>&1'
  ]

  for (const cmd of testCommands) {
    try {
      const output = execSync(cmd, {
        cwd: projectDir,
        encoding: 'utf-8',
        timeout: 60000,
        env: { ...process.env, CI: 'true' }
      })
      return output.trim()
    } catch (err: unknown) {
      // Test command failed — capture the output (this is what we want)
      const execErr = err as { stdout?: string; stderr?: string } | null
      if (execErr?.stdout || execErr?.stderr) {
        return `${execErr.stdout ?? ''}\n${execErr.stderr ?? ''}`.trim()
      }
    }
  }

  return null
}

/**
 * Extract stack traces from output text.
 */
export function extractStackTrace(output: string): string | null {
  const lines = output.split('\n')
  const traceLines: string[] = []
  let inTrace = false

  for (const line of lines) {
    if (line.match(/^\s+at\s/) || line.match(/Error:/i) || line.match(/^\s+\^/)) {
      inTrace = true
      traceLines.push(line)
    } else if (inTrace && line.trim() === '') {
      break
    } else if (inTrace) {
      traceLines.push(line)
    }
  }

  return traceLines.length > 0 ? traceLines.join('\n') : null
}

/**
 * Build the full error context for a failed subtask.
 */
export function collectErrorContext(opts: {
  projectDir: string
  originalPrompt: string
  agentOutput: string[]
  screenshot?: string | null
  vlmAnalysis?: string | null
}): ErrorContext {
  const consoleOutput = opts.agentOutput.join('\n')

  return {
    screenshot: opts.screenshot ?? null,
    apiResponse: null, // populated by the validation step if applicable
    testOutput: collectTestOutput(opts.projectDir),
    consoleOutput,
    stackTrace: extractStackTrace(consoleOutput),
    diff: collectGitDiff(opts.projectDir),
    vlmAnalysis: opts.vlmAnalysis ?? null,
    originalPrompt: opts.originalPrompt
  }
}

/**
 * Build a descriptive error prompt that tells the agent exactly what went wrong.
 * This is the key to the self-healing loop.
 */
export function buildErrorPrompt(ctx: ErrorContext): string {
  const parts: string[] = []

  parts.push(`You were asked to: ${ctx.originalPrompt}`)
  parts.push('')
  parts.push('Here\'s what happened:')

  if (ctx.testOutput) {
    parts.push('')
    parts.push('## Test Output')
    parts.push('```')
    // Trim to last 80 lines to save tokens
    const lines = ctx.testOutput.split('\n')
    parts.push(lines.slice(-80).join('\n'))
    parts.push('```')
  }

  if (ctx.stackTrace) {
    parts.push('')
    parts.push('## Stack Trace')
    parts.push('```')
    parts.push(ctx.stackTrace)
    parts.push('```')
  }

  if (ctx.apiResponse) {
    parts.push('')
    parts.push('## API Error Response')
    parts.push('```')
    parts.push(ctx.apiResponse.slice(0, 2000))
    parts.push('```')
  }

  if (ctx.diff) {
    parts.push('')
    parts.push('## Your Changes (git diff)')
    parts.push('```diff')
    // Trim large diffs to save tokens
    const diffLines = ctx.diff.split('\n')
    parts.push(diffLines.slice(0, 100).join('\n'))
    if (diffLines.length > 100) parts.push(`... (${diffLines.length - 100} more lines)`)
    parts.push('```')
  }

  if (ctx.vlmAnalysis) {
    parts.push('')
    parts.push('## Visual Analysis')
    parts.push(ctx.vlmAnalysis)
  }

  parts.push('')
  parts.push('Fix these issues. Be precise — address each error directly.')

  return parts.join('\n')
}
