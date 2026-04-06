/**
 * Bayesian Risk Propagation — propagates compromise probability through
 * the attack graph's dependency edges.
 *
 * Key insight: If Auth Service has a 70% chance of being compromised,
 * and Payment API depends on Auth with a 0.8 propagation weight,
 * then Payment API's risk increases even if it has no direct vulnerabilities.
 *
 * Uses iterative belief propagation until convergence.
 */

import type { AttackGraph, Service, Dependency } from './types'

const MAX_ITERATIONS = 50
const CONVERGENCE_THRESHOLD = 0.001

/**
 * Propagate risk through the attack graph.
 * Returns a map of serviceId -> final propagated risk score (0-1).
 */
export function propagateRisk(graph: AttackGraph): Map<string, number> {
  const riskScores = new Map<string, number>()

  // Initialize with base compromise probabilities
  for (const service of graph.services) {
    riskScores.set(service.id, service.baseCompromiseProbability)
  }

  // Build dependency lookup: target -> [{source, weight}]
  const incomingEdges = new Map<string, { from: string; weight: number }[]>()
  for (const service of graph.services) {
    incomingEdges.set(service.id, [])
  }
  for (const dep of graph.dependencies) {
    // dep.from depends on dep.to
    // If dep.to is compromised, dep.from's risk increases
    // But also: if dep.from is compromised (e.g. Auth), services that depend on it (dep.to via reverse) are at risk
    // We model: compromise propagates FROM a compromised service TO services that depend on it
    const dependents = graph.reverseAdjacency.get(dep.to) ?? []
    // Actually, let's think about this correctly:
    // dep.from -> dep.to means "from depends on to"
    // If "to" is compromised, "from" is at risk (because from relies on to)
    incomingEdges.get(dep.from)!.push({ from: dep.to, weight: dep.propagationWeight })
  }

  // Also propagate in the other direction: if A is compromised and B depends on A,
  // B might be compromised through the dependency.
  // This is actually the main attack vector: compromised upstream -> downstream at risk
  for (const dep of graph.dependencies) {
    // from depends on to. If from is compromised, it might compromise to through the connection
    // But more commonly: if to (upstream) is compromised, from (downstream) is at risk
    // We already handle that above. Let's also handle the reverse:
    // If Auth (from=Portal, to=Auth means Portal depends on Auth)
    // Auth compromised -> Portal at risk (handled above)
    // Portal compromised -> Auth at risk? Only if there's a reverse path, which there isn't typically.
    // So the above is correct. Let's proceed.
  }

  // Iterative propagation
  let converged = false
  let iteration = 0

  while (!converged && iteration < MAX_ITERATIONS) {
    converged = true
    iteration++

    for (const service of graph.services) {
      const baseRisk = service.baseCompromiseProbability
      const incoming = incomingEdges.get(service.id) ?? []

      if (incoming.length === 0) {
        // No dependencies — risk stays at base level
        continue
      }

      // P(compromised) = 1 - P(not compromised by own vulns) * P(not compromised via any dependency)
      // P(not compromised via dep_i) = 1 - P(dep_i compromised) * weight_i
      let survivalFromDeps = 1
      for (const edge of incoming) {
        const depRisk = riskScores.get(edge.from) ?? 0
        survivalFromDeps *= (1 - depRisk * edge.weight)
      }

      // Combined: own vulnerability risk OR propagated risk
      const ownSurvival = 1 - baseRisk
      const newRisk = 1 - (ownSurvival * survivalFromDeps)

      const oldRisk = riskScores.get(service.id) ?? 0
      const delta = Math.abs(newRisk - oldRisk)

      if (delta > CONVERGENCE_THRESHOLD) {
        converged = false
      }

      riskScores.set(service.id, newRisk)
    }
  }

  // Update service objects with propagated scores
  for (const service of graph.services) {
    service.currentRiskScore = riskScores.get(service.id) ?? 0
  }

  return riskScores
}

/**
 * Recompute risk after patching specific vulnerabilities.
 * Returns updated risk scores for all services.
 */
export function recomputeRiskAfterPatching(
  graph: AttackGraph,
  patchedCveIds: Set<string>
): Map<string, number> {
  // Temporarily mark vulnerabilities as patched
  const originalStatuses = new Map<string, string>()
  for (const vuln of graph.vulnerabilities) {
    originalStatuses.set(vuln.id, vuln.status)
    if (patchedCveIds.has(vuln.id)) {
      vuln.status = 'patched'
    }
  }

  // Recompute base probabilities
  for (const service of graph.services) {
    const openVulns = graph.vulnerabilities.filter(v =>
      v.affectedServiceIds.includes(service.id) && v.status === 'open'
    )
    if (openVulns.length === 0) {
      service.baseCompromiseProbability = 0
    } else {
      const survival = openVulns.reduce((acc, v) => acc * (1 - v.exploitProbability), 1)
      service.baseCompromiseProbability = 1 - survival
    }
  }

  // Re-propagate
  const newScores = propagateRisk(graph)

  // Restore original statuses
  for (const vuln of graph.vulnerabilities) {
    vuln.status = originalStatuses.get(vuln.id) as 'open' | 'in-progress' | 'patched' | 'verified'
  }

  // Restore original base probabilities
  for (const service of graph.services) {
    const openVulns = graph.vulnerabilities.filter(v =>
      v.affectedServiceIds.includes(service.id) && originalStatuses.get(v.id) === 'open'
    )
    if (openVulns.length === 0) {
      service.baseCompromiseProbability = 0
    } else {
      const survival = openVulns.reduce((acc, v) => acc * (1 - v.exploitProbability), 1)
      service.baseCompromiseProbability = 1 - survival
    }
  }

  return newScores
}

/**
 * Compute the total weighted system risk from a risk score map.
 */
export function computeTotalRiskFromScores(
  services: Service[],
  riskScores: Map<string, number>
): number {
  const tierWeights: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
  let totalWeightedRisk = 0
  let totalWeight = 0

  for (const s of services) {
    const weight = tierWeights[s.tier] ?? 1
    totalWeightedRisk += (riskScores.get(s.id) ?? 0) * weight
    totalWeight += weight
  }

  return totalWeight > 0 ? totalWeightedRisk / totalWeight : 0
}
