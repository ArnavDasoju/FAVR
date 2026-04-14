/**
 * Unit tests for diff mode logic.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { runDiff } from '../src/diff.js'
import { setStorePath, saveScanResult } from '@favr/core'
import { writeFileSync, mkdirSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import type { ScanResult, AnalysisResult } from '@favr/core'

const testDir = join(tmpdir(), `favr-diff-test-${Date.now()}`)
const storePath = join(testDir, 'scan-history.json')

function makeMockAnalysis(vulns: any[]): AnalysisResult {
  return {
    graph: {
      services: [{
        id: 'svc-1', name: 'test', techStack: [], tier: 'high' as const,
        sla: 99.9, description: '', baseCompromiseProbability: 0.5,
        currentRiskScore: 0.5, complianceFrameworks: [], maintenanceWindow: null
      }],
      dependencies: [],
      vulnerabilities: vulns
    },
    riskScores: {},
    simulation: {
      optimalOrder: [], naiveOrder: [], optimalCurve: [], naiveCurve: [],
      confidenceIntervals: [], totalRiskBefore: 0.5, totalRiskAfter: 0.1,
      riskReduction: 80, iterations: 100, convergenceScore: 0.9
    },
    pareto: { solutions: [], frontierIds: [] },
    blastRadii: {},
    schedule: [],
    complianceSummary: { frameworks: [], violations: [], overallComplianceRisk: 0 },
    timestamp: Date.now(),
    engineVersion: '2.1.0'
  }
}

function makeVuln(cveId: string, severity: string, cvssScore: number) {
  return {
    id: cveId, cveId, title: `Vuln ${cveId}`, description: '',
    severity, cvssScore, epssScore: 0.1, exploitProbability: 0.3,
    affectedServiceIds: ['svc-1'], affectedPackage: 'pkg@1.0.0',
    patchedVersion: 'pkg@2.0.0', remediationCost: 2, remediationDowntime: 5,
    complexity: 'low' as const, status: 'open' as const, patchOrder: null,
    constraints: [], knownExploit: false, complianceViolations: [],
    complianceDeadlineDays: null
  }
}

beforeEach(() => {
  mkdirSync(testDir, { recursive: true })
  setStorePath(storePath)
})

afterEach(() => {
  rmSync(testDir, { recursive: true, force: true })
})

describe('runDiff', () => {
  it('treats all vulns as new when no previous scan exists', () => {
    const current: ScanResult = {
      projectPath: '/fake/project',
      projectName: 'fake',
      discoveryStats: {} as any,
      analysis: makeMockAnalysis([makeVuln('CVE-1', 'high', 7.5)])
    }

    const diff = runDiff('/fake/project', current)
    expect(diff.newVulns).toHaveLength(1)
    expect(diff.worsenedVulns).toHaveLength(0)
    expect(diff.summary).toContain('No previous scan found')
  })

  it('detects new vulnerabilities', () => {
    // Save a previous scan with one vuln
    const prevAnalysis = makeMockAnalysis([makeVuln('CVE-1', 'medium', 5.0)])
    saveScanResult({
      projectPath: '/fake/project',
      projectName: 'fake',
      timestamp: Date.now() - 60000,
      durationMs: 100,
      stats: {} as any,
      analysisJson: JSON.stringify(prevAnalysis),
      snapshot: { timestamp: Date.now(), projectDir: '/fake/project', fileHashes: {}, cachedCveData: {} }
    })

    // Current scan has the old vuln + a new one
    const current: ScanResult = {
      projectPath: '/fake/project',
      projectName: 'fake',
      discoveryStats: {} as any,
      analysis: makeMockAnalysis([
        makeVuln('CVE-1', 'medium', 5.0),
        makeVuln('CVE-2', 'critical', 9.8)
      ])
    }

    const diff = runDiff('/fake/project', current)
    expect(diff.newVulns).toHaveLength(1)
    expect(diff.newVulns[0].cveId).toBe('CVE-2')
    expect(diff.unchangedCount).toBe(1)
  })

  it('detects worsened vulnerabilities', () => {
    // Previous: CVE-1 was medium
    const prevAnalysis = makeMockAnalysis([makeVuln('CVE-1', 'medium', 5.0)])
    saveScanResult({
      projectPath: '/fake/project',
      projectName: 'fake',
      timestamp: Date.now() - 60000,
      durationMs: 100,
      stats: {} as any,
      analysisJson: JSON.stringify(prevAnalysis),
      snapshot: { timestamp: Date.now(), projectDir: '/fake/project', fileHashes: {}, cachedCveData: {} }
    })

    // Current: CVE-1 is now critical
    const current: ScanResult = {
      projectPath: '/fake/project',
      projectName: 'fake',
      discoveryStats: {} as any,
      analysis: makeMockAnalysis([makeVuln('CVE-1', 'critical', 9.8)])
    }

    const diff = runDiff('/fake/project', current)
    expect(diff.worsenedVulns).toHaveLength(1)
    expect(diff.worsenedVulns[0].previousSeverity).toBe('medium')
    expect(diff.worsenedVulns[0].severity).toBe('critical')
  })

  it('reports unchanged when nothing changed', () => {
    const analysis = makeMockAnalysis([makeVuln('CVE-1', 'high', 7.5)])
    saveScanResult({
      projectPath: '/fake/project',
      projectName: 'fake',
      timestamp: Date.now() - 60000,
      durationMs: 100,
      stats: {} as any,
      analysisJson: JSON.stringify(analysis),
      snapshot: { timestamp: Date.now(), projectDir: '/fake/project', fileHashes: {}, cachedCveData: {} }
    })

    const current: ScanResult = {
      projectPath: '/fake/project',
      projectName: 'fake',
      discoveryStats: {} as any,
      analysis: makeMockAnalysis([makeVuln('CVE-1', 'high', 7.5)])
    }

    const diff = runDiff('/fake/project', current)
    expect(diff.newVulns).toHaveLength(0)
    expect(diff.worsenedVulns).toHaveLength(0)
    expect(diff.unchangedCount).toBe(1)
  })
})
