/**
 * FAVR Core — the headless analysis engine.
 *
 * Zero Electron dependencies. Can be used from CLI, CI/CD, or the desktop app.
 *
 * Primary entry point:
 *   const result = await scan('/path/to/project', { onProgress: console.log })
 */

import { analyzeCodebase, type CodebaseAnalysisResult, type AnalyzerProgressCallback, type ScanSnapshot } from './ingest/codebase-analyzer.js'
import { runAnalysis, type AnalysisResult, type ProgressCallback, type AnalysisProgress } from './engine/index.js'
import { generateReport } from './engine/report.js'
import { runWhatIf } from './engine/what-if.js'
import { getLatestSnapshot, saveScanResult, getLatestScan, setStorePath } from './ingest/scan-history.js'
import { resolve } from 'path'
import { basename } from 'path'

// ─── Primary Scan Function ──────────────────────────────────

export interface ScanOptions {
  /** Analysis iterations (default: 500) */
  iterations?: number
  /** Timeout for codebase discovery in ms (default: 120_000) */
  timeoutMs?: number
  /** Use previous scan snapshot for incremental scanning */
  incremental?: boolean
  /** Progress callback for the discovery phase */
  onDiscoveryProgress?: AnalyzerProgressCallback
  /** Progress callback for the analysis engine */
  onAnalysisProgress?: ProgressCallback
}

export interface ScanResult {
  /** The full analysis result from the engine */
  analysis: AnalysisResult
  /** Stats from the codebase discovery phase */
  discoveryStats: CodebaseAnalysisResult['stats']
  /** The project path that was scanned */
  projectPath: string
  /** The project name (dirname) */
  projectName: string
}

/**
 * Scan a project directory for vulnerabilities and produce an optimal patching plan.
 *
 * This is the primary entry point for FAVR. It:
 * 1. Discovers services, dependencies, and packages in the codebase
 * 2. Queries OSV.dev for known vulnerabilities
 * 3. Builds an attack graph and runs Bayesian risk propagation
 * 4. Runs Monte Carlo simulation to find optimal patch ordering
 * 5. Computes Pareto frontier, blast radii, schedule, and compliance summary
 */
export async function scan(projectPath: string, options: ScanOptions = {}): Promise<ScanResult> {
  const resolvedPath = resolve(projectPath)
  const projectName = basename(resolvedPath)

  // Phase 1: Codebase discovery
  const previousSnapshot = options.incremental ? getLatestSnapshot(resolvedPath) : null

  const discoveryResult = await analyzeCodebase({
    projectDir: resolvedPath,
    onProgress: options.onDiscoveryProgress,
    timeoutMs: options.timeoutMs,
    previousScan: previousSnapshot
  })

  // Phase 2: Analysis engine
  const analysis = await runAnalysis({
    services: discoveryResult.services,
    dependencies: discoveryResult.dependencies,
    vulnerabilities: discoveryResult.vulnerabilities,
    iterations: options.iterations,
    onProgress: options.onAnalysisProgress
  })

  // Phase 3: Save to scan history
  const snapshot = (discoveryResult as any)._snapshot as ScanSnapshot | undefined
  if (snapshot) {
    saveScanResult({
      projectPath: resolvedPath,
      projectName,
      timestamp: Date.now(),
      durationMs: discoveryResult.stats.scanDurationMs,
      stats: discoveryResult.stats,
      analysisJson: JSON.stringify(analysis),
      snapshot
    })
  }

  return {
    analysis,
    discoveryStats: discoveryResult.stats,
    projectPath: resolvedPath,
    projectName
  }
}

// ─── Re-exports ─────────────────────────────────────────────

// Engine
export { runAnalysis, generateReport, runWhatIf }
export { buildAttackGraph } from './engine/attack-graph.js'
export type {
  AnalysisResult, AnalysisProgress, ProgressCallback,
  Service, Dependency, Vulnerability, Severity,
  SimulationResult, ParetoSolution, ParetoFrontier,
  AttackGraph, ConfidenceInterval, VulnConstraint,
  BlastRadius, ScheduledPatch, WhatIfConstraints, WhatIfResult,
  ComplianceFramework, MaintenanceWindow
} from './engine/types.js'

// Ingest
export { analyzeCodebase } from './ingest/codebase-analyzer.js'
export type { CodebaseAnalysisResult, AnalyzerProgressCallback, ScanSnapshot } from './ingest/codebase-analyzer.js'
export { scanCodebase } from './ingest/scanner.js'
export { parseDocuments } from './ingest/parser.js'

// Scan history
export {
  saveScanResult, listScanHistory, getProjectHistory,
  loadScanResult, getLatestScan, getLatestSnapshot,
  deleteScanResult, clearScanHistory, setStorePath
} from './ingest/scan-history.js'

// Demo data
export { loadMeridianScenario } from './data/meridian-scenario.js'
