/**
 * Compliance Engine — computes regulatory exposure across all services and vulns.
 *
 * Maps vulnerabilities to compliance frameworks, identifies violations,
 * and computes an overall compliance risk score.
 */

import type { AttackGraph, ComplianceFramework, Vulnerability, Service } from './types.js'

export interface ComplianceSummary {
  frameworks: ComplianceFramework[]
  violations: {
    framework: ComplianceFramework
    vulnIds: string[]
    urgentCount: number  // vulns with deadline < 14 days
  }[]
  overallComplianceRisk: number  // 0-1
}

/**
 * Compute compliance summary from the attack graph.
 */
export function computeComplianceSummary(graph: AttackGraph): ComplianceSummary {
  const openVulns = graph.vulnerabilities.filter(v => v.status === 'open')

  // Collect all frameworks in use
  const frameworkSet = new Set<ComplianceFramework>()
  for (const s of graph.services) {
    for (const f of (s.complianceFrameworks ?? [])) {
      frameworkSet.add(f)
    }
  }
  for (const v of openVulns) {
    for (const f of (v.complianceViolations ?? [])) {
      frameworkSet.add(f)
    }
  }

  const frameworks = Array.from(frameworkSet).sort()

  // Build violations per framework
  const violations = frameworks.map(framework => {
    // Direct violations: vulns that explicitly list this framework
    const directViolations = openVulns.filter(v =>
      (v.complianceViolations ?? []).includes(framework)
    )

    // Indirect violations: vulns on services under this framework
    const servicesUnderFramework = new Set(
      graph.services
        .filter(s => (s.complianceFrameworks ?? []).includes(framework))
        .map(s => s.id)
    )
    const indirectViolations = openVulns.filter(v =>
      v.affectedServiceIds.some(sid => servicesUnderFramework.has(sid)) &&
      !directViolations.includes(v)
    )

    const allVulnIds = [
      ...directViolations.map(v => v.id),
      ...indirectViolations.map(v => v.id)
    ]

    // Urgent: deadline < 14 days
    const urgentCount = directViolations.filter(v =>
      v.complianceDeadlineDays !== null && v.complianceDeadlineDays <= 14
    ).length

    return { framework, vulnIds: allVulnIds, urgentCount }
  }).filter(v => v.vulnIds.length > 0)

  // Overall compliance risk: weighted by framework importance and urgency
  const frameworkWeights: Record<string, number> = {
    'PCI-DSS': 1.0,
    'HIPAA': 0.95,
    'SOX': 0.9,
    'GDPR': 0.85,
    'SOC2': 0.7,
    'NIST': 0.6,
    'ISO27001': 0.5
  }

  let riskSum = 0
  let weightSum = 0

  for (const v of violations) {
    const weight = frameworkWeights[v.framework] ?? 0.5
    const vulnRisk = v.vulnIds.length / Math.max(openVulns.length, 1)
    const urgencyBoost = v.urgentCount > 0 ? 1.5 : 1.0
    riskSum += vulnRisk * weight * urgencyBoost
    weightSum += weight
  }

  const overallComplianceRisk = weightSum > 0 ? Math.min(1, riskSum / weightSum) : 0

  return { frameworks, violations, overallComplianceRisk }
}
