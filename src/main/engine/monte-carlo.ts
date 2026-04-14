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
import { propagateRisk, computeTotalRiskFromScores, effectiveExploitProb } from './bayesian'
import { getCalibration } from './calibration'

const DEFAULT_ITERATIONS = 500

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

  // Collect per-iteration baseline risks for confidence bands
  const iterationBaselines: number[] = []

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
    // Step 1: Perturb exploit probabilities with exploitability context.
    // High-confidence threats (public exploit + KEV + remote) get narrower, higher distributions.
    // Unknown/low-confidence threats get wider uncertainty ranges.
    const cal = getCalibration()
    for (const vuln of openVulns) {
      const base = originalProbs.get(vuln.id)!

      // Compute exploitability multiplier from real-world context
      let multiplier = 1.0
      if (vuln.hasPublicExploit || vuln.knownExploit) multiplier *= cal.knownExploitMultiplier
      if (vuln.inKev) multiplier *= cal.kevMultiplier
      if (vuln.attackVector === 'network') multiplier *= cal.remoteExploitMultiplier

      // High-confidence threats: narrow perturbation, biased upward
      // Low-confidence: wider perturbation, centered
      const isHighConfidence = multiplier > 2.0
      const range = isHighConfidence
        ? cal.perturbationRange * 0.5  // tighter band for well-known threats
        : cal.perturbationRange

      const noise = (Math.random() * 2 - 1) * range
      // Apply multiplier to base, then add noise
      const boosted = Math.min(base * Math.sqrt(multiplier), 0.98)
      const floor = isHighConfidence ? cal.perturbationFloorHighConfidence : cal.minExploitProbability
      vuln.exploitProbability = clamp(boosted + boosted * noise, floor, 0.99)
    }

    // Step 2: Greedy patch ordering (also returns baseline risk for confidence bands)
    const { ordering, baseline } = greedyPatchOrder(graph, openVulns)
    iterationBaselines.push(baseline)

    // Step 3: Record positions
    for (let pos = 0; pos < ordering.length; pos++) {
      const vulnId = ordering[pos]
      positionCounts[pos].set(vulnId, (positionCounts[pos].get(vulnId) ?? 0) + 1)
    }

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

  // Compute risk confidence bands from per-iteration baselines + optimal curve
  const cal = getCalibration()
  const riskConfidence = computeRiskConfidenceFromBaselines(
    iterationBaselines, optimalCurve, cal.confidenceLower, cal.confidenceUpper
  )

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
    convergenceScore,
    riskConfidence
  }
}

/**
 * Marginal-contribution ordering: for each vuln, compute the real total-risk
 * reduction from patching it alone, sort descending. O(N) propagation calls
 * per iteration vs the old full-greedy's O(N²).
 *
 * This captures each vuln's true first-order marginal contribution (not an
 * estimate), but skips the inner greedy that re-evaluates at every step.
 * MC perturbation + position voting across iterations still converges on a
 * stable ordering.
 */
function greedyPatchOrder(graph: AttackGraph, openVulns: Vulnerability[]): { ordering: string[]; baseline: number } {
  // Baseline: real total system risk with nothing patched (reflects perturbed exploit probs)
  const baseline = computeRiskWithPatched(graph, new Set<string>())

  // For each vuln, the real reduction from patching it alone
  const scored = openVulns.map(v => {
    const riskAfter = computeRiskWithPatched(graph, new Set<string>([v.id]))
    return { id: v.id, reduction: baseline - riskAfter }
  })

  scored.sort((a, b) => b.reduction - a.reduction)
  return { ordering: scored.map(s => s.id), baseline }
}

/**
 * Compute total system risk with a set of vulnerabilities marked as patched.
 */
function computeRiskWithPatched(graph: AttackGraph, patchedIds: Set<string>): number {
  // Recompute base probabilities with patched vulns removed, using EPSS-weighted blend
  for (const service of graph.services) {
    const openVulns = graph.vulnerabilities.filter(v =>
      v.affectedServiceIds.includes(service.id) &&
      v.status === 'open' &&
      !patchedIds.has(v.id)
    )
    if (openVulns.length === 0) {
      service.baseCompromiseProbability = 0
    } else {
      const survival = openVulns.reduce((acc, v) => acc * (1 - effectiveExploitProb(v)), 1)
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

/**
 * Compute confidence bands from per-iteration baseline risks and the optimal risk curve.
 *
 * The marginal-contribution algorithm doesn't track full per-iteration curves (too expensive).
 * Instead, we collect each iteration's baseline risk (before patching) under perturbed
 * probabilities, then scale the optimal curve proportionally to derive confidence bands.
 */
function computeRiskConfidenceFromBaselines(
  baselines: number[],
  optimalCurve: number[],
  lowerPct: number,
  upperPct: number
): SimulationResult['riskConfidence'] {
  if (baselines.length === 0 || optimalCurve.length === 0) {
    return {
      meanBefore: 0, lowerBefore: 0, upperBefore: 0,
      meanAfter: 0, lowerAfter: 0, upperAfter: 0,
      curveBands: [[0, 0, 0]]
    }
  }

  const sorted = [...baselines].sort((a, b) => a - b)
  const n = sorted.length
  const lowerBefore = sorted[Math.floor(n * lowerPct)] ?? sorted[0]
  const upperBefore = sorted[Math.min(Math.floor(n * upperPct), n - 1)] ?? sorted[n - 1]
  const meanBefore = sorted.reduce((s, v) => s + v, 0) / n

  // The optimal curve starts at the deterministic baseline (optimalCurve[0]) and
  // ends near zero. Scale each step proportionally by the ratio of percentile
  // baseline to the deterministic baseline.
  const deterministicBaseline = optimalCurve[0] || 1
  const lowerScale = lowerBefore / deterministicBaseline
  const upperScale = upperBefore / deterministicBaseline

  const curveBands: [number, number, number][] = optimalCurve.map(risk => {
    const meanRisk = risk * (meanBefore / deterministicBaseline)
    return [risk * lowerScale, meanRisk, risk * upperScale]
  })

  const last = curveBands[curveBands.length - 1]

  return {
    meanBefore,
    lowerBefore,
    upperBefore,
    meanAfter: last[1],
    lowerAfter: last[0],
    upperAfter: last[2],
    curveBands
  }
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
    convergenceScore: 1,
    riskConfidence: {
      meanBefore: 0, lowerBefore: 0, upperBefore: 0,
      meanAfter: 0, lowerAfter: 0, upperAfter: 0,
      curveBands: [[0, 0, 0]]
    }
  }
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}
