/**
 * Diff mode — compares the current scan against the most recent scan from history.
 *
 * Reports:
 * - New vulnerabilities (present now but not in the previous scan)
 * - Worsened vulnerabilities (severity increased since last scan)
 * - Summary line with counts
 */

import { getLatestScan, type ScanResult, type AnalysisResult, type Vulnerability } from '@favr/core'

export interface DiffVuln {
  cveId: string
  severity: string
  cvssScore: number
  title: string
  affectedPackage: string
  previousSeverity?: string
}

export interface DiffResult {
  newVulns: DiffVuln[]
  worsenedVulns: DiffVuln[]
  unchangedCount: number
  summary: string
  fullResult: ScanResult
}

const SEVERITY_ORDER: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
}

export function runDiff(projectPath: string, currentResult: ScanResult): DiffResult {
  const previousEntry = getLatestScan(projectPath)

  if (!previousEntry) {
    // No previous scan — treat all current vulns as new
    const currentVulns = currentResult.analysis.graph.vulnerabilities.filter(v => v.status === 'open')
    return {
      newVulns: currentVulns.map(v => ({
        cveId: v.cveId,
        severity: v.severity,
        cvssScore: v.cvssScore,
        title: v.title,
        affectedPackage: v.affectedPackage
      })),
      worsenedVulns: [],
      unchangedCount: 0,
      summary: `No previous scan found. ${currentVulns.length} vulnerabilities detected (all treated as new).`,
      fullResult: currentResult
    }
  }

  let previousAnalysis: AnalysisResult
  try {
    previousAnalysis = JSON.parse(previousEntry.analysisJson)
  } catch {
    return {
      newVulns: [],
      worsenedVulns: [],
      unchangedCount: 0,
      summary: 'Previous scan data is corrupted. Run a fresh scan.',
      fullResult: currentResult
    }
  }

  const previousVulns = new Map<string, Vulnerability>()
  for (const v of previousAnalysis.graph.vulnerabilities) {
    previousVulns.set(v.cveId, v)
  }

  const currentVulns = currentResult.analysis.graph.vulnerabilities.filter(v => v.status === 'open')
  const newVulns: DiffVuln[] = []
  const worsenedVulns: DiffVuln[] = []
  let unchangedCount = 0

  for (const v of currentVulns) {
    const prev = previousVulns.get(v.cveId)
    if (!prev) {
      newVulns.push({
        cveId: v.cveId,
        severity: v.severity,
        cvssScore: v.cvssScore,
        title: v.title,
        affectedPackage: v.affectedPackage
      })
    } else if ((SEVERITY_ORDER[v.severity] ?? 0) > (SEVERITY_ORDER[prev.severity] ?? 0)) {
      worsenedVulns.push({
        cveId: v.cveId,
        severity: v.severity,
        cvssScore: v.cvssScore,
        title: v.title,
        affectedPackage: v.affectedPackage,
        previousSeverity: prev.severity
      })
    } else {
      unchangedCount++
    }
  }

  const parts: string[] = []
  if (newVulns.length > 0) parts.push(`${newVulns.length} new`)
  if (worsenedVulns.length > 0) parts.push(`${worsenedVulns.length} worsened`)
  parts.push(`${unchangedCount} unchanged`)

  const summary = parts.join(', ') + ` vulnerabilit${unchangedCount === 1 ? 'y' : 'ies'}.`

  return { newVulns, worsenedVulns, unchangedCount, summary, fullResult: currentResult }
}
