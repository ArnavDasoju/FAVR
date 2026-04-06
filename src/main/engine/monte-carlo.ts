/**
 * Monte Carlo Simulation Engine — runs thousands of simulations
 * to find the optimal vulnerability patching order.
 *
 * Each iteration:
 * 1. Perturb exploit probabilities by ±20% (models uncertainty)
 * 2. Use greedy selection: at each step, pick the patch that maximally reduces total risk
 * 3. Track cumulative risk exposure curve
 * 4. Record which CVE appeared at each position
 *
 * Output: the most frequent optimal ordering, confidence intervals,
 * and comparison against naive severity-sort.
 */

import type {
  AttackGraph, Service, Dependency, Vulnerability,
  SimulationResult, ConfidenceInterval
} from './types'
import { propagateRisk, computeTotalRiskFromScores } from './bayesian'

const DEFAULT_ITERATIONS = 10000
const PERTURBATION_RANGE = 0.2  // ±20%

/**
 * Run Monte Carlo simulation to find optimal patch ordering.
 */
export function runMonteCarlo(
  graph: AttackGraph,
  iterations: number = DEFAULT_ITERATIONS,
  onProgress?: (pct: number) => void
): SimulationResult {
  const openVulns = graph.vulnerabilities.filter(v => v.status === 'open')
  const n = openVulns.length

  if (n === 0) {
    return emptyResult()
  }

  // Track how often each CVE appears at each position
  // positionCounts[position][vulnId] = count
  const positionCounts: Map<string, number>[] = Array.from({ length: n }, () => new Map())

  // Track total risk curves per iteration
  const allOptimalCurves: number[][] = []

  // Save original probabilities
  const originalProbs = new Map<string, number>()
  for (const v of openVulns) {
    originalProbs.set(v.id, v.exploitProbability)
  }
  const originalServiceProbs = new Map<string, number>()
  for (const s of graph.services) {
    originalServiceProbs.set(s.id, s.baseCompromiseProbability)
  }

  for (let iter = 0; iter < iterations; iter++) {
    // Step 1: Perturb exploit probabilities
    for (const vuln of openVulns) {
      const base = originalProbs.get(vuln.id)!
      const noise = (Math.random() * 2 - 1) * PERTURBATION_RANGE  // uniform [-0.2, 0.2]
      vuln.exploitProbability = clamp(base + base * noise, 0.01, 0.99)
    }

    // Step 2: Greedy patch ordering
    const ordering = greedyPatchOrder(graph, openVulns)

    // Step 3: Record positions
    for (let pos = 0; pos < ordering.length; pos++) {
      const vulnId = ordering[pos]
      positionCounts[pos].set(vulnId, (positionCounts[pos].get(vulnId) ?? 0) + 1)
    }

    // Step 4: Compute risk curve for this ordering
    const curve = computeRiskCurve(graph, ordering)
    allOptimalCurves.push(curve)

    // Progress
    if (onProgress && iter % Math.max(1, Math.floor(iterations / 100)) === 0) {
      onProgress(Math.floor((iter / iterations) * 100))
    }
  }

  // Restore original probabilities
  for (const vuln of openVulns) {
    vuln.exploitProbability = originalProbs.get(vuln.id)!
  }
  for (const s of graph.services) {
    s.baseCompromiseProbability = originalServiceProbs.get(s.id)!
  }

  // Determine optimal ordering: most frequent CVE at each position
  const optimalOrder = buildOptimalOrdering(positionCounts, openVulns)

  // Compute the risk curve for the optimal ordering (with original probabilities)
  const optimalCurve = computeRiskCurve(graph, optimalOrder)

  // Compute naive ordering (sort by CVSS descending)
  const naiveOrder = [...openVulns]
    .sort((a, b) => b.cvssScore - a.cvssScore || b.exploitProbability - a.exploitProbability)
    .map(v => v.id)
  const naiveCurve = computeRiskCurve(graph, naiveOrder)

  // Build confidence intervals
  const confidenceIntervals = buildConfidenceIntervals(positionCounts, optimalOrder, iterations)

  // Compute convergence score: average frequency of the most-common CVE at each position
  const convergenceScore = confidenceIntervals.reduce((sum, ci) => sum + ci.frequency, 0) / n

  const totalRiskBefore = optimalCurve[0]
  const totalRiskAfter = optimalCurve[optimalCurve.length - 1]

  return {
    optimalOrder,
    naiveOrder,
    optimalCurve,
    naiveCurve,
    confidenceIntervals,
    totalRiskBefore,
    totalRiskAfter,
    riskReduction: totalRiskBefore > 0 ? ((totalRiskBefore - totalRiskAfter) / totalRiskBefore) * 100 : 0,
    iterations,
    convergenceScore
  }
}

/**
 * Greedy patch ordering: at each step, pick the CVE whose patching
 * results in the maximum total risk reduction.
 */
function greedyPatchOrder(graph: AttackGraph, openVulns: Vulnerability[]): string[] {
  const order: string[] = []
  const patched = new Set<string>()
  const remaining = new Set(openVulns.map(v => v.id))

  while (remaining.size > 0) {
    let bestVuln: string | null = null
    let bestRiskAfter = Infinity

    for (const vulnId of remaining) {
      // Simulate patching this one
      const testPatched = new Set(patched)
      testPatched.add(vulnId)

      const risk = computeRiskWithPatched(graph, testPatched)

      if (risk < bestRiskAfter) {
        bestRiskAfter = risk
        bestVuln = vulnId
      }
    }

    if (bestVuln) {
      order.push(bestVuln)
      patched.add(bestVuln)
      remaining.delete(bestVuln)
    } else {
      // Shouldn't happen, but handle gracefully
      const next = remaining.values().next().value!
      order.push(next)
      patched.add(next)
      remaining.delete(next)
    }
  }

  return order
}

/**
 * Compute total system risk with a set of vulnerabilities marked as patched.
 */
function computeRiskWithPatched(graph: AttackGraph, patchedIds: Set<string>): number {
  // Recompute base probabilities with patched vulns removed
  for (const service of graph.services) {
    const openVulns = graph.vulnerabilities.filter(v =>
      v.affectedServiceIds.includes(service.id) &&
      v.status === 'open' &&
      !patchedIds.has(v.id)
    )
    if (openVulns.length === 0) {
      service.baseCompromiseProbability = 0
    } else {
      const survival = openVulns.reduce((acc, v) => acc * (1 - v.exploitProbability), 1)
      service.baseCompromiseProbability = 1 - survival
    }
  }

  // Propagate and compute total
  const scores = propagateRisk(graph)
  return computeTotalRiskFromScores(graph.services, scores)
}

/**
 * Compute the cumulative risk curve for a given patch ordering.
 * Returns an array of length n+1: [riskBefore, riskAfter1, riskAfter2, ..., riskAfterAll]
 */
function computeRiskCurve(graph: AttackGraph, ordering: string[]): number[] {
  // Save original base probs
  const originalBaseProbs = new Map<string, number>()
  for (const s of graph.services) {
    originalBaseProbs.set(s.id, s.baseCompromiseProbability)
  }

  const curve: number[] = []
  const patched = new Set<string>()

  // Risk before any patching
  curve.push(computeRiskWithPatched(graph, patched))

  // Risk after each successive patch
  for (const vulnId of ordering) {
    patched.add(vulnId)
    curve.push(computeRiskWithPatched(graph, patched))
  }

  // Restore original base probs
  for (const s of graph.services) {
    s.baseCompromiseProbability = originalBaseProbs.get(s.id)!
  }

  return curve
}

/**
 * Build the optimal ordering from position frequency counts.
 * At each position, pick the CVE that appeared most frequently
 * (and hasn't already been placed).
 */
function buildOptimalOrdering(
  positionCounts: Map<string, number>[],
  openVulns: Vulnerability[]
): string[] {
  const order: string[] = []
  const placed = new Set<string>()

  for (let pos = 0; pos < positionCounts.length; pos++) {
    const counts = positionCounts[pos]
    let bestId: string | null = null
    let bestCount = -1

    for (const [vulnId, count] of counts) {
      if (!placed.has(vulnId) && count > bestCount) {
        bestCount = count
        bestId = vulnId
      }
    }

    if (bestId) {
      order.push(bestId)
      placed.add(bestId)
    }
  }

  // Any remaining vulns not placed (shouldn't happen but safety)
  for (const v of openVulns) {
    if (!placed.has(v.id)) {
      order.push(v.id)
    }
  }

  return order
}

/**
 * Build confidence intervals showing how stable each position is.
 */
function buildConfidenceIntervals(
  positionCounts: Map<string, number>[],
  optimalOrder: string[],
  totalIterations: number
): ConfidenceInterval[] {
  return optimalOrder.map((cveId, pos) => {
    const counts = positionCounts[pos]
    const frequency = (counts.get(cveId) ?? 0) / totalIterations

    // Get alternatives at this position
    const alternatives: { cveId: string; frequency: number }[] = []
    for (const [id, count] of counts) {
      if (id !== cveId) {
        alternatives.push({ cveId: id, frequency: count / totalIterations })
      }
    }
    alternatives.sort((a, b) => b.frequency - a.frequency)

    return {
      position: pos,
      cveId,
      frequency,
      alternatives: alternatives.slice(0, 3)  // top 3 alternatives
    }
  })
}

function emptyResult(): SimulationResult {
  return {
    optimalOrder: [],
    naiveOrder: [],
    optimalCurve: [0],
    naiveCurve: [0],
    confidenceIntervals: [],
    totalRiskBefore: 0,
    totalRiskAfter: 0,
    riskReduction: 0,
    iterations: 0,
    convergenceScore: 1
  }
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}
