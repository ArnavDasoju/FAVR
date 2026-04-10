/**
 * What-If Scenario Engine — re-optimizes under user-defined constraints.
 *
 * Supports:
 * - Budget constraint (max person-hours)
 * - Skip specific services or vulns
 * - Max downtime constraint
 * - Shows residual risk and compliance gaps
 */

import type {
  AttackGraph, WhatIfConstraints, WhatIfResult,
  ComplianceFramework, Vulnerability
} from './types'
import { propagateRisk, computeTotalRiskFromScores } from './bayesian'

/**
 * Run a what-if scenario: given constraints, which vulns can we patch
 * and what's the residual risk?
 */
export function runWhatIf(
  graph: AttackGraph,
  optimalOrder: string[],
  constraints: WhatIfConstraints
): WhatIfResult {
  const vulnMap = new Map(graph.vulnerabilities.map(v => [v.id, v]))
  const patchableVulns: string[] = []
  const skippedVulns: string[] = []

  let totalCost = 0
  let totalDowntime = 0

  // Walk the optimal order, include vulns that fit the constraints
  for (const vulnId of optimalOrder) {
    const vuln = vulnMap.get(vulnId)
    if (!vuln || vuln.status !== 'open') continue

    // Skip if vuln or its services are excluded
    if (constraints.skipVulnIds.includes(vulnId)) {
      skippedVulns.push(vulnId)
      continue
    }
    if (vuln.affectedServiceIds.some(sid => constraints.skipServiceIds.includes(sid))) {
      skippedVulns.push(vulnId)
      continue
    }

    // Check budget
    if (constraints.maxBudgetHours !== null && totalCost + vuln.remediationCost > constraints.maxBudgetHours) {
      skippedVulns.push(vulnId)
      continue
    }

    // Check downtime
    if (constraints.maxDowntimeMinutes !== null && totalDowntime + vuln.remediationDowntime > constraints.maxDowntimeMinutes) {
      skippedVulns.push(vulnId)
      continue
    }

    patchableVulns.push(vulnId)
    totalCost += vuln.remediationCost
    totalDowntime += vuln.remediationDowntime
  }

  // Compute residual risk with only patchable vulns applied
  const patchedSet = new Set(patchableVulns)

  // Save and modify base probabilities
  const origProbs = new Map<string, number>()
  for (const s of graph.services) {
    origProbs.set(s.id, s.baseCompromiseProbability)
  }

  for (const service of graph.services) {
    const remainingVulns = graph.vulnerabilities.filter(v =>
      v.affectedServiceIds.includes(service.id) &&
      v.status === 'open' &&
      !patchedSet.has(v.id)
    )
    if (remainingVulns.length === 0) {
      service.baseCompromiseProbability = 0
    } else {
      const survival = remainingVulns.reduce((acc, v) => {
        const epss = v.epssScore ?? v.exploitProbability
        const effective = 0.6 * epss + 0.4 * v.exploitProbability
        return acc * (1 - effective)
      }, 1)
      service.baseCompromiseProbability = 1 - survival
    }
  }

  const scores = propagateRisk(graph)
  const residualRisk = computeTotalRiskFromScores(graph.services, scores)

  const residualRiskByService: Record<string, number> = {}
  for (const [id, score] of scores) {
    residualRiskByService[id] = score
  }

  // Restore
  for (const s of graph.services) {
    s.baseCompromiseProbability = origProbs.get(s.id)!
  }

  // Compute compliance gaps: which frameworks still have open vulns?
  const complianceGaps = computeComplianceGaps(graph, skippedVulns, vulnMap)

  return {
    constraints,
    patchableVulns,
    skippedVulns,
    residualRisk,
    residualRiskByService,
    totalCost,
    totalDowntime,
    complianceGaps
  }
}

function computeComplianceGaps(
  graph: AttackGraph,
  skippedVulnIds: string[],
  vulnMap: Map<string, Vulnerability>
): { framework: ComplianceFramework; vulnIds: string[] }[] {
  const gaps = new Map<ComplianceFramework, Set<string>>()

  for (const vulnId of skippedVulnIds) {
    const vuln = vulnMap.get(vulnId)
    if (!vuln) continue

    // Direct compliance violations that remain
    for (const framework of (vuln.complianceViolations ?? [])) {
      if (!gaps.has(framework)) gaps.set(framework, new Set())
      gaps.get(framework)!.add(vulnId)
    }

    // Also check if skipped vuln's services are under compliance
    for (const sid of vuln.affectedServiceIds) {
      const service = graph.services.find(s => s.id === sid)
      if (!service) continue
      for (const framework of (service.complianceFrameworks ?? [])) {
        if (!gaps.has(framework)) gaps.set(framework, new Set())
        gaps.get(framework)!.add(vulnId)
      }
    }
  }

  return Array.from(gaps.entries())
    .map(([framework, vulnIds]) => ({ framework, vulnIds: Array.from(vulnIds) }))
    .sort((a, b) => b.vulnIds.length - a.vulnIds.length)
}
