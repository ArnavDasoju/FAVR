/**
 * Unit tests for CLI output formatters.
 */

import { describe, it, expect } from 'vitest'
import { formatJson } from '../src/formatters/json.js'
import { formatTable } from '../src/formatters/table.js'
import { formatSarif } from '../src/formatters/sarif.js'
import { formatHtml } from '../src/formatters/html.js'
import type { ScanResult } from '@favr/core'

const mockResult: ScanResult = {
  projectPath: '/tmp/test-project',
  projectName: 'test-project',
  discoveryStats: {
    servicesFound: 1,
    packagesScanned: 3,
    vulnerabilitiesFound: 2,
    ecosystems: ['npm'],
    unresolvedPackages: 0,
    dockerImagesScanned: 0,
    isMonorepo: false,
    scanDurationMs: 100
  },
  analysis: {
    graph: {
      services: [{
        id: 'svc-1', name: 'test-svc', techStack: ['Node.js'], tier: 'high',
        sla: 99.9, description: 'Test', baseCompromiseProbability: 0.5,
        currentRiskScore: 0.6, complianceFrameworks: [], maintenanceWindow: null
      }],
      dependencies: [],
      vulnerabilities: [
        {
          id: 'vuln-1', cveId: 'CVE-2024-0001', title: 'Test Critical Vuln',
          description: 'A critical test vulnerability', severity: 'critical',
          cvssScore: 9.8, epssScore: 0.5, exploitProbability: 0.7,
          affectedServiceIds: ['svc-1'], affectedPackage: 'express@4.17.1',
          patchedVersion: 'express@4.19.0', remediationCost: 4,
          remediationDowntime: 10, complexity: 'medium', status: 'open',
          patchOrder: 1, constraints: [], knownExploit: true,
          complianceViolations: ['PCI-DSS'], complianceDeadlineDays: 30
        },
        {
          id: 'vuln-2', cveId: 'CVE-2024-0002', title: 'Test Medium Vuln',
          description: 'A medium test vulnerability', severity: 'medium',
          cvssScore: 5.5, epssScore: 0.1, exploitProbability: 0.2,
          affectedServiceIds: ['svc-1'], affectedPackage: 'lodash@4.17.20',
          patchedVersion: 'lodash@4.17.21', remediationCost: 2,
          remediationDowntime: 0, complexity: 'low', status: 'open',
          patchOrder: 2, constraints: [], knownExploit: false,
          complianceViolations: [], complianceDeadlineDays: null
        }
      ]
    },
    riskScores: { 'svc-1': 0.6 },
    simulation: {
      optimalOrder: ['vuln-1', 'vuln-2'],
      naiveOrder: ['vuln-1', 'vuln-2'],
      optimalCurve: [0.6, 0.3, 0.0],
      naiveCurve: [0.6, 0.35, 0.0],
      confidenceIntervals: [],
      totalRiskBefore: 0.6,
      totalRiskAfter: 0.0,
      riskReduction: 100,
      iterations: 500,
      convergenceScore: 0.95
    },
    pareto: { solutions: [], frontierIds: [] },
    blastRadii: {},
    schedule: [],
    complianceSummary: {
      frameworks: ['PCI-DSS'] as any,
      violations: [{ framework: 'PCI-DSS' as any, vulnIds: ['vuln-1'], urgentCount: 1 }],
      overallComplianceRisk: 0.4
    },
    timestamp: Date.now(),
    engineVersion: '2.1.0'
  }
}

describe('JSON formatter', () => {
  it('produces valid JSON', () => {
    const output = formatJson(mockResult)
    const parsed = JSON.parse(output)
    expect(parsed).toBeDefined()
    expect(parsed.projectName).toBe('test-project')
  })

  it('includes all expected top-level keys', () => {
    const parsed = JSON.parse(formatJson(mockResult))
    expect(parsed).toHaveProperty('projectPath')
    expect(parsed).toHaveProperty('summary')
    expect(parsed).toHaveProperty('vulnerabilities')
    expect(parsed).toHaveProperty('optimalPatchOrder')
  })

  it('reports correct vulnerability counts', () => {
    const parsed = JSON.parse(formatJson(mockResult))
    expect(parsed.summary.totalVulnerabilities).toBe(2)
    expect(parsed.summary.critical).toBe(1)
    expect(parsed.summary.medium).toBe(1)
  })
})

describe('Table formatter', () => {
  it('produces non-empty output', () => {
    const output = formatTable(mockResult)
    expect(output.length).toBeGreaterThan(0)
  })

  it('includes project name', () => {
    const output = formatTable(mockResult)
    expect(output).toContain('test-project')
  })

  it('includes CVE IDs', () => {
    const output = formatTable(mockResult)
    expect(output).toContain('CVE-2024-0001')
  })
})

describe('SARIF formatter', () => {
  it('produces valid SARIF 2.1.0 JSON', () => {
    const output = formatSarif(mockResult)
    const parsed = JSON.parse(output)
    expect(parsed.version).toBe('2.1.0')
    expect(parsed.$schema).toContain('sarif-schema-2.1.0')
  })

  it('has correct tool name', () => {
    const parsed = JSON.parse(formatSarif(mockResult))
    expect(parsed.runs[0].tool.driver.name).toBe('FAVR')
  })

  it('maps critical severity to error level', () => {
    const parsed = JSON.parse(formatSarif(mockResult))
    const criticalResult = parsed.runs[0].results.find((r: any) => r.ruleId === 'CVE-2024-0001')
    expect(criticalResult.level).toBe('error')
  })

  it('maps medium severity to warning level', () => {
    const parsed = JSON.parse(formatSarif(mockResult))
    const mediumResult = parsed.runs[0].results.find((r: any) => r.ruleId === 'CVE-2024-0002')
    expect(mediumResult.level).toBe('warning')
  })

  it('includes security-severity in rule properties', () => {
    const parsed = JSON.parse(formatSarif(mockResult))
    const rule = parsed.runs[0].tool.driver.rules[0]
    expect(rule.properties['security-severity']).toBe('9.8')
  })

  it('has one rule per vulnerability', () => {
    const parsed = JSON.parse(formatSarif(mockResult))
    expect(parsed.runs[0].tool.driver.rules.length).toBe(2)
    expect(parsed.runs[0].results.length).toBe(2)
  })
})

describe('HTML formatter', () => {
  it('produces valid HTML', () => {
    const output = formatHtml(mockResult)
    expect(output).toContain('<!DOCTYPE html>')
    expect(output).toContain('FAVR')
  })
})
