/**
 * JSON formatter — pretty-printed, clean JSON to stdout.
 * Nothing else on stdout so pipes work.
 */

import type { ScanResult } from '@favr/core'

export function formatJson(result: ScanResult): string {
  const { analysis, discoveryStats, projectPath, projectName } = result
  const vulns = analysis.graph.vulnerabilities

  return JSON.stringify({
    projectPath,
    projectName,
    timestamp: new Date(analysis.timestamp).toISOString(),
    engineVersion: analysis.engineVersion,
    discoveryStats,
    summary: {
      totalVulnerabilities: vulns.length,
      critical: vulns.filter(v => v.severity === 'critical').length,
      high: vulns.filter(v => v.severity === 'high').length,
      medium: vulns.filter(v => v.severity === 'medium').length,
      low: vulns.filter(v => v.severity === 'low').length,
      riskBefore: analysis.simulation.totalRiskBefore,
      riskAfter: analysis.simulation.totalRiskAfter,
      riskReduction: analysis.simulation.riskReduction
    },
    optimalPatchOrder: analysis.simulation.optimalOrder.map((id, i) => {
      const v = vulns.find(x => x.id === id)
      return v ? {
        position: i + 1,
        id: v.id,
        cveId: v.cveId,
        severity: v.severity,
        cvssScore: v.cvssScore,
        epssScore: v.epssScore,
        affectedPackage: v.affectedPackage,
        patchedVersion: v.patchedVersion,
        title: v.title,
        remediationCost: v.remediationCost,
        remediationDowntime: v.remediationDowntime
      } : { position: i + 1, id }
    }),
    vulnerabilities: vulns.map(v => ({
      id: v.id,
      cveId: v.cveId,
      title: v.title,
      description: v.description,
      severity: v.severity,
      cvssScore: v.cvssScore,
      epssScore: v.epssScore,
      affectedPackage: v.affectedPackage,
      patchedVersion: v.patchedVersion,
      affectedServiceIds: v.affectedServiceIds,
      remediationCost: v.remediationCost,
      remediationDowntime: v.remediationDowntime,
      status: v.status,
      knownExploit: v.knownExploit,
      complianceViolations: v.complianceViolations
    })),
    services: analysis.graph.services.map(s => ({
      id: s.id,
      name: s.name,
      tier: s.tier,
      riskScore: analysis.riskScores[s.id] ?? 0,
      complianceFrameworks: s.complianceFrameworks
    })),
    complianceSummary: analysis.complianceSummary
  }, null, 2)
}
