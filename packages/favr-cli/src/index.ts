#!/usr/bin/env node

/**
 * FAVR CLI — scan codebases for vulnerabilities from the terminal or CI/CD.
 *
 * Usage:
 *   favr-scan <project-path>
 *   favr-scan . --format json --threshold high
 *   favr-scan . --format sarif --output results.sarif --diff
 */

import { Command } from 'commander'
import { scan, type ScanResult } from '@favr/core'
import { formatTable } from './formatters/table.js'
import { formatJson } from './formatters/json.js'
import { formatHtml } from './formatters/html.js'
import { formatSarif } from './formatters/sarif.js'
import { loadConfig, mergeConfigWithFlags, type FavrConfig } from './config.js'
import { runDiff } from './diff.js'
import { resolve } from 'path'
import { writeFileSync } from 'fs'

const program = new Command()

program
  .name('favr-scan')
  .description('Scan a codebase for vulnerabilities and produce an optimal patching plan')
  .version('0.1.0')
  .argument('<project-path>', 'Path to the project directory to scan')
  .option('-f, --format <format>', 'Output format: table, json, html, sarif', 'table')
  .option('-t, --threshold <threshold>', 'Fail if any finding meets or exceeds this severity (low/medium/high/critical) or CVSS score (e.g. 7.0)')
  .option('-o, --output <file>', 'Write output to a file instead of stdout (for html/sarif)')
  .option('-c, --config <path>', 'Path to config file (.favr.yml, .favr.yaml, or .favr.json)')
  .option('--diff', 'Compare against last scan — only report new or worsened vulnerabilities')
  .option('--iterations <n>', 'Number of Monte Carlo iterations (default: 500)', parseInt)
  .option('--no-progress', 'Suppress progress output')
  .action(async (projectPath: string, opts: Record<string, any>) => {
    const resolvedPath = resolve(projectPath)
    const format: string = opts.format
    const isDataFormat = format === 'json' || format === 'sarif'

    // Load and merge config
    let config: FavrConfig = {}
    try {
      config = loadConfig(opts.config, resolvedPath)
    } catch (err) {
      logStderr(`Error loading config: ${(err as Error).message}`)
      process.exit(2)
    }
    const merged = mergeConfigWithFlags(config, opts)

    // Progress output (only in non-data formats, and when --progress is on)
    const showProgress = opts.progress !== false && !isDataFormat
    const onProgress = showProgress
      ? (p: { phase: string; progress: number; message: string }) => {
          logStderr(`[${p.phase}] ${p.message}`)
        }
      : undefined

    try {
      // Run the scan
      const result = await scan(resolvedPath, {
        iterations: merged.iterations,
        onDiscoveryProgress: onProgress,
        onAnalysisProgress: onProgress ? (p) => onProgress({ phase: p.phase, progress: p.progress, message: p.message }) : undefined,
        incremental: true
      })

      // Filter ignored CVEs from config
      if (merged.ignoredCves && merged.ignoredCves.length > 0) {
        const ignored = new Set(merged.ignoredCves)
        result.analysis.graph.vulnerabilities = result.analysis.graph.vulnerabilities.filter(
          v => !ignored.has(v.cveId)
        )
      }

      // Diff mode
      if (opts.diff) {
        const diffResult = runDiff(resolvedPath, result)
        await outputDiffResult(diffResult, format, opts.output, merged)
        return
      }

      // Output
      await outputResult(result, format, opts.output)

      // Threshold check
      if (merged.threshold) {
        const exceeded = checkThreshold(result, merged.threshold)
        if (exceeded) {
          logStderr(`\nThreshold exceeded: found findings at or above ${merged.threshold}`)
          process.exit(1)
        }
      }
    } catch (err) {
      logStderr(`Error: ${(err as Error).message}`)
      process.exit(2)
    }
  })

program.parse()

// ─── Helpers ────────────────────────────────────────────────

function logStderr(msg: string): void {
  process.stderr.write(msg + '\n')
}

async function outputResult(result: ScanResult, format: string, outputFile?: string): Promise<void> {
  switch (format) {
    case 'table':
      process.stdout.write(formatTable(result) + '\n')
      break
    case 'json':
      process.stdout.write(formatJson(result) + '\n')
      break
    case 'html': {
      const html = formatHtml(result)
      const file = outputFile ?? 'favr-report.html'
      writeFileSync(file, html)
      logStderr(`Report written to ${file}`)
      break
    }
    case 'sarif': {
      const sarif = formatSarif(result)
      if (outputFile) {
        writeFileSync(outputFile, sarif)
        logStderr(`SARIF written to ${outputFile}`)
      } else {
        process.stdout.write(sarif + '\n')
      }
      break
    }
    default:
      logStderr(`Unknown format: ${format}`)
      process.exit(2)
  }
}

interface DiffOutput {
  newVulns: any[]
  worsenedVulns: any[]
  unchangedCount: number
  summary: string
  fullResult: ScanResult
}

async function outputDiffResult(
  diff: DiffOutput,
  format: string,
  outputFile: string | undefined,
  config: any
): Promise<void> {
  // In diff mode, exit 0 if nothing new or worsened, regardless of threshold
  const hasIssues = diff.newVulns.length > 0 || diff.worsenedVulns.length > 0

  switch (format) {
    case 'table':
      process.stdout.write(diff.summary + '\n')
      if (diff.newVulns.length > 0) {
        process.stdout.write('\nNew vulnerabilities:\n')
        for (const v of diff.newVulns) {
          process.stdout.write(`  - ${v.cveId} (${v.severity}, CVSS ${v.cvssScore}) — ${v.title}\n`)
        }
      }
      if (diff.worsenedVulns.length > 0) {
        process.stdout.write('\nWorsened vulnerabilities:\n')
        for (const v of diff.worsenedVulns) {
          process.stdout.write(`  - ${v.cveId} (${v.previousSeverity} → ${v.severity}, CVSS ${v.cvssScore}) — ${v.title}\n`)
        }
      }
      break
    case 'json':
      process.stdout.write(JSON.stringify({
        newVulnerabilities: diff.newVulns,
        worsenedVulnerabilities: diff.worsenedVulns,
        unchangedCount: diff.unchangedCount,
        summary: diff.summary
      }, null, 2) + '\n')
      break
    case 'sarif': {
      // In diff mode, SARIF only includes new/worsened
      const filteredResult = { ...diff.fullResult }
      const relevantIds = new Set([
        ...diff.newVulns.map((v: any) => v.cveId),
        ...diff.worsenedVulns.map((v: any) => v.cveId)
      ])
      filteredResult.analysis = {
        ...filteredResult.analysis,
        graph: {
          ...filteredResult.analysis.graph,
          vulnerabilities: filteredResult.analysis.graph.vulnerabilities.filter(
            v => relevantIds.has(v.cveId)
          )
        }
      }
      const sarif = formatSarif(filteredResult)
      if (outputFile) {
        writeFileSync(outputFile, sarif)
        logStderr(`SARIF written to ${outputFile}`)
      } else {
        process.stdout.write(sarif + '\n')
      }
      break
    }
    case 'html': {
      const html = formatHtml(diff.fullResult)
      const file = outputFile ?? 'favr-report.html'
      writeFileSync(file, html)
      logStderr(`Report written to ${file}`)
      break
    }
  }

  if (hasIssues) {
    logStderr(diff.summary)
    process.exit(1)
  } else {
    logStderr(diff.summary)
    process.exit(0)
  }
}

function checkThreshold(result: ScanResult, threshold: string): boolean {
  const vulns = result.analysis.graph.vulnerabilities.filter(v => v.status === 'open')

  // Try parsing as a number (CVSS score)
  const numericThreshold = parseFloat(threshold)
  if (!isNaN(numericThreshold)) {
    return vulns.some(v => v.cvssScore >= numericThreshold)
  }

  // Parse as severity label
  const severityOrder: Record<string, number> = {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }

  const thresholdLevel = severityOrder[threshold.toLowerCase()]
  if (!thresholdLevel) {
    logStderr(`Invalid threshold: ${threshold}. Use low, medium, high, critical, or a CVSS score.`)
    process.exit(2)
  }

  return vulns.some(v => (severityOrder[v.severity] ?? 0) >= thresholdLevel)
}
