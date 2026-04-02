/**
 * Validation Orchestrator — the complete self-healing loop.
 *
 * Flow:
 * 1. Agent completes a subtask
 * 2. Collect error context (tests, diff, console)
 * 3. Take screenshot of dev server (if available)
 * 4. Send to VLM for confidence scoring
 * 5. Route based on confidence:
 *    - ≥85%: auto-approve
 *    - 5-84%: build descriptive error prompt → retry
 *    - <5%: notify user (too broken to self-heal)
 */

import { captureScreenshot, captureConsoleErrors, isServerReachable } from './screenshot'
import { validateWithVlm, validateTextOnly } from './vlm'
import { collectErrorContext, buildErrorPrompt, type ErrorContext } from './error-collector'
import { executeAndValidate } from './executor'
import type { QueuedSubtask } from '../tasks/queue'

export interface ValidationPipelineResult {
  confidence: number
  reasoning: string
  issues: string[]
  errorContext: ErrorContext
  errorPrompt: string | null // built retry prompt, null if approved
  screenshot: string | null // base64
  executionOutput: string | null // stdout from running the code
  executionCommand: string | null // what was run
  executionSuccess: boolean | null // did it exit 0?
  executionReasoning: string | null // verification detail (expected vs actual)
}

export interface ValidatorConfig {
  geminiApiKey: string | null
  confidenceThreshold: number // default 85
}

/**
 * Run the full validation pipeline for a completed subtask.
 */
export async function runValidation(opts: {
  subtask: QueuedSubtask
  projectDir: string
  devServerUrl: string | null
  agentOutput: string[]
  changedFiles?: string[]
  config: ValidatorConfig
}): Promise<ValidationPipelineResult> {
  const { subtask, projectDir, devServerUrl, agentOutput, config } = opts
  const changedFiles = opts.changedFiles ?? []

  // Step 0: Execute the code and check if it actually runs + verify output
  let execResult: ReturnType<typeof executeAndValidate> | null = null
  if (changedFiles.length > 0) {
    execResult = executeAndValidate(projectDir, changedFiles, subtask.originalPrompt)
    console.log(`[validator] Execution: confidence=${execResult.confidence}, ran=${execResult.ran}, exit=${execResult.exitCode}, match=${execResult.outputMatch}`)
  }

  // Step 1: Collect error context (tests, diff, stack traces)
  const errorContext = collectErrorContext({
    projectDir,
    originalPrompt: subtask.prompt,
    agentOutput
  })

  // Add execution results to error context
  if (execResult?.ran && execResult.exitCode !== 0) {
    errorContext.testOutput = (errorContext.testOutput ?? '') + '\n\nExecution output:\n' + (execResult.stderr || execResult.stdout)
    if (!errorContext.stackTrace && execResult.stderr) {
      const { extractStackTrace } = require('./error-collector')
      errorContext.stackTrace = extractStackTrace(execResult.stderr)
    }
  }

  // Step 2: Take screenshot if dev server is available
  let screenshot: string | null = null
  let consoleErrors: string[] = []

  if (devServerUrl) {
    const reachable = await isServerReachable(devServerUrl)
    if (reachable) {
      const result = await captureScreenshot(devServerUrl)
      screenshot = result?.base64 ?? null
      consoleErrors = await captureConsoleErrors(devServerUrl)
      errorContext.screenshot = screenshot
    }
  }

  // Step 2b: Read actual file contents of changed files (so VLM can see the code)
  let fileContents: string | null = null
  if (changedFiles.length > 0) {
    const { readFileSync } = require('fs')
    const { join } = require('path')
    const fileParts: string[] = []
    for (const f of changedFiles.slice(0, 5)) {
      try {
        const content = readFileSync(join(projectDir, f), 'utf-8')
        fileParts.push(`--- ${f} ---\n${content.slice(0, 3000)}`)
      } catch { /* ignore */ }
    }
    if (fileParts.length > 0) {
      fileContents = fileParts.join('\n\n')
    }
  }

  // Step 3: VLM validation
  let confidence: number
  let reasoning: string
  let issues: string[]

  const execExtras = {
    fileContents,
    executionOutput: execResult?.stdout || execResult?.stderr || null,
    executionCommand: execResult?.command ?? null,
    executionSuccess: execResult?.ran ? execResult.exitCode === 0 : null
  }

  if (config.geminiApiKey) {
    const vlmResult = devServerUrl
      ? await validateWithVlm({
          apiKey: config.geminiApiKey,
          prompt: subtask.prompt,
          beforeScreenshot: null,
          afterScreenshot: screenshot,
          diff: errorContext.diff,
          testOutput: errorContext.testOutput,
          consoleErrors,
          ...execExtras
        })
      : await validateTextOnly({
          apiKey: config.geminiApiKey,
          prompt: subtask.prompt,
          diff: errorContext.diff,
          testOutput: errorContext.testOutput,
          ...execExtras
        })

    confidence = vlmResult.confidence
    reasoning = vlmResult.reasoning
    issues = vlmResult.issues
    errorContext.vlmAnalysis = vlmResult.reasoning
  } else {
    // No Gemini key — fall back to heuristic validation
    const heuristic = heuristicValidation(errorContext)
    confidence = heuristic.confidence
    reasoning = heuristic.reasoning
    issues = heuristic.issues
  }

  // Add console errors to issues
  if (consoleErrors.length > 0) {
    issues.push(...consoleErrors.map((e) => `Console error: ${e}`))
    confidence = Math.max(0, confidence - consoleErrors.length * 5)
  }

  // Factor in execution results — execution is the strongest signal
  if (execResult?.ran) {
    if (execResult.exitCode === 0) {
      // Code ran successfully — boost confidence
      confidence = Math.max(confidence, execResult.confidence)
      console.log(`[validator] Execution passed — boosting confidence to ${confidence}`)
    } else {
      // Code failed to run — cap confidence
      confidence = Math.min(confidence, execResult.confidence)
      issues.push(`Execution failed: ${execResult.reasoning}`)
      console.log(`[validator] Execution failed — capping confidence to ${confidence}`)
    }
  }

  // Step 4: Build error prompt if retry is needed
  let errorPrompt: string | null = null
  if (confidence < config.confidenceThreshold) {
    errorPrompt = buildErrorPrompt(errorContext)
  }

  return {
    confidence,
    reasoning,
    issues,
    errorContext,
    errorPrompt,
    screenshot,
    executionOutput: execResult?.ran ? (execResult.stdout || execResult.stderr || null) : null,
    executionCommand: execResult?.command ?? null,
    executionSuccess: execResult?.ran ? execResult.exitCode === 0 : null,
    executionReasoning: execResult?.reasoning ?? null
  }
}

/**
 * Heuristic validation when no VLM is available.
 * Checks test output and diff for obvious issues.
 */
function heuristicValidation(ctx: ErrorContext): {
  confidence: number
  reasoning: string
  issues: string[]
} {
  const issues: string[] = []
  let confidence = 70 // start neutral

  // Check test output
  if (ctx.testOutput) {
    const lower = ctx.testOutput.toLowerCase()
    if (lower.includes('fail') || lower.includes('error')) {
      confidence -= 30
      issues.push('Tests are failing')
    } else if (lower.includes('pass') || lower.includes('✓') || lower.includes('✔')) {
      confidence += 20
    }
  }

  // Check for stack traces
  if (ctx.stackTrace) {
    confidence -= 20
    issues.push('Stack trace detected in output')
  }

  // Check diff exists (agent actually made changes)
  // Skip this check if no git repo — files may have been written by file-applier
  if (!ctx.diff && ctx.consoleOutput && !ctx.consoleOutput.includes('Applied changes to')) {
    confidence -= 10
    issues.push('No code changes detected')
  }

  // Check console output for errors
  if (ctx.consoleOutput) {
    const errorCount = (ctx.consoleOutput.match(/error/gi) || []).length
    if (errorCount > 0) {
      confidence -= errorCount * 5
      issues.push(`${errorCount} error(s) in agent output`)
    }
  }

  confidence = Math.max(0, Math.min(100, confidence))

  const reasoning =
    issues.length === 0 ? 'No obvious issues detected (heuristic check)' : `Issues found: ${issues.join('; ')}`

  return { confidence, reasoning, issues }
}
