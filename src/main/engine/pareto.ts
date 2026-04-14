/**
 * Pareto Multi-Objective Optimization — finds the set of non-dominated
 * solutions across three competing objectives:
 *
 * 1. Risk Reduction (minimize residual risk)
 * 2. Cost (minimize total person-hours)
 * 3. Downtime (minimize total service downtime)
 *
 * Key insight: We evaluate PARTIAL orderings at different budget levels.
 * "If you can only spend 10 hours, which 4 CVEs should you patch?"
 * This creates meaningful tradeoffs on the Pareto frontier.
 */

import type { AttackGraph, Vulnerability, ParetoSolution, ParetoFrontier } from './types'
import { propagateRisk, computeTotalRiskFromScores, effectiveExploitProb } from './bayesian'

/**
 * Find the Pareto frontier by evaluating different subsets of patches
 * at various budget levels.
 */
export function findParetoFrontier(
  graph: AttackGraph,
  optimalOrder: string[],
  naiveOrder: string[]
): ParetoFrontier {
  const openVulns = graph.vulnerabilities.filter(v => v.status === 'open')
  const vulnMap = new Map(openVulns.map(v => [v.id, v]))

  const solutions: ParetoSolution[] = []
  let solCounter = 0

  // Strategy: evaluate each ordering at every prefix length (1, 2, 3, ... N patches)
  // This creates solutions with different cost/risk/downtime tradeoffs

  const orderings: { order: string[]; label: string }[] = [
    { order: optimalOrder, label: 'Risk Optimized' },
    { order: naiveOrder, label: 'Severity Sort' },
    { order: sortByCost(openVulns), label: 'Cost First' },
    { order: sortByDowntime(openVulns), label: 'Min Downtime' },
    { order: sortByCostEfficiency(openVulns), label: 'Best Efficiency' },
    { order: sortByCriticality(openVulns, graph), label: 'Critical Services First' },
  ]

  // Add some random orderings for diversity
  for (let i = 0; i < 10; i++) {
    orderings.push({ order: shuffleArray(openVulns.map(v => v.id)), label: `Random ${i + 1}` })
  }

  for (const { order, label } of orderings) {
    // Evaluate at each prefix length
    for (let patchCount = 1; patchCount <= order.length; patchCount++) {
      const subset = order.slice(0, patchCount)
      const metrics = evaluateSubset(graph, subset, vulnMap)

      solutions.push({
        id: `sol-${solCounter++}`,
        patchOrder: subset,
        totalRisk: metrics.residualRisk,
        totalCost: metrics.totalCost,
        totalDowntime: metrics.totalDowntime,
        dominated: false,
        label: patchCount === order.length ? `${label} (All)` :
               patchCount <= 3 ? `${label} (Top ${patchCount})` : undefined
      })
    }
  }

  // Non-dominated sorting
  for (let i = 0; i < solutions.length; i++) {
    for (let j = 0; j < solutions.length; j++) {
      if (i === j) continue
      if (dominates(solutions[j], solutions[i])) {
        solutions[i].dominated = true
        break
      }
    }
  }

  // Deduplicate close solutions on the frontier
  const frontier = deduplicateSolutions(solutions.filter(s => !s.dominated))

  // Label key frontier points
  if (frontier.length > 0) {
    // Find extremes
    const lowestRisk = frontier.reduce((a, b) => a.totalRisk < b.totalRisk ? a : b)
    const lowestCost = frontier.reduce((a, b) => a.totalCost < b.totalCost ? a : b)
    const lowestDowntime = frontier.reduce((a, b) => a.totalDowntime < b.totalDowntime ? a : b)

    if (!lowestRisk.label) lowestRisk.label = 'Lowest Risk'
    if (!lowestCost.label && lowestCost.id !== lowestRisk.id) lowestCost.label = 'Lowest Cost'
    if (!lowestDowntime.label && lowestDowntime.id !== lowestRisk.id && lowestDowntime.id !== lowestCost.id) {
      lowestDowntime.label = 'Least Downtime'
    }

    // Find a balanced option (closest to center of frontier)
    if (frontier.length >= 3) {
      const avgRisk = frontier.reduce((s, f) => s + f.totalRisk, 0) / frontier.length
      const avgCost = frontier.reduce((s, f) => s + f.totalCost, 0) / frontier.length
      const avgDown = frontier.reduce((s, f) => s + f.totalDowntime, 0) / frontier.length

      const balanced = frontier.reduce((best, curr) => {
        const bestDist = Math.abs(best.totalRisk - avgRisk) + Math.abs(best.totalCost - avgCost) / 10 + Math.abs(best.totalDowntime - avgDown) / 50
        const currDist = Math.abs(curr.totalRisk - avgRisk) + Math.abs(curr.totalCost - avgCost) / 10 + Math.abs(curr.totalDowntime - avgDown) / 50
        return currDist < bestDist ? curr : best
      })

      if (!balanced.label) balanced.label = 'Balanced'
    }
  }

  return {
    solutions,
    frontierIds: frontier.map(s => s.id)
  }
}

/**
 * Check if solution A dominates solution B.
 */
function dominates(a: ParetoSolution, b: ParetoSolution): boolean {
  const betterOrEqual =
    a.totalRisk <= b.totalRisk &&
    a.totalCost <= b.totalCost &&
    a.totalDowntime <= b.totalDowntime

  const strictlyBetter =
    a.totalRisk < b.totalRisk ||
    a.totalCost < b.totalCost ||
    a.totalDowntime < b.totalDowntime

  return betterOrEqual && strictlyBetter
}

/**
 * Evaluate a subset of patches: compute residual risk, total cost, total downtime.
 */
function evaluateSubset(
  graph: AttackGraph,
  patchIds: string[],
  vulnMap: Map<string, Vulnerability>
): { residualRisk: number; totalCost: number; totalDowntime: number } {
  const origProbs = new Map<string, number>()
  for (const s of graph.services) {
    origProbs.set(s.id, s.baseCompromiseProbability)
  }

  const patched = new Set(patchIds)
  let totalCost = 0
  let totalDowntime = 0

  for (const vulnId of patchIds) {
    const vuln = vulnMap.get(vulnId)
    if (!vuln) continue
    totalCost += vuln.remediationCost
    totalDowntime += vuln.remediationDowntime
  }

  // Compute residual risk with these patches applied
  for (const service of graph.services) {
    const remainingVulns = graph.vulnerabilities.filter(v =>
      v.affectedServiceIds.includes(service.id) &&
      v.status === 'open' &&
      !patched.has(v.id)
    )
    if (remainingVulns.length === 0) {
      service.baseCompromiseProbability = 0
    } else {
      const survival = remainingVulns.reduce((acc, v) => acc * (1 - effectiveExploitProb(v)), 1)
      service.baseCompromiseProbability = 1 - survival
    }
  }

  const scores = propagateRisk(graph)
  const residualRisk = computeTotalRiskFromScores(graph.services, scores)

  // Restore
  for (const s of graph.services) {
    s.baseCompromiseProbability = origProbs.get(s.id)!
  }

  return { residualRisk, totalCost, totalDowntime }
}

// ─── Ordering Strategies ──────────────────────────────────────

function sortByCost(vulns: Vulnerability[]): string[] {
  return [...vulns].sort((a, b) => a.remediationCost - b.remediationCost).map(v => v.id)
}

function sortByDowntime(vulns: Vulnerability[]): string[] {
  return [...vulns].sort((a, b) => a.remediationDowntime - b.remediationDowntime).map(v => v.id)
}

function sortByCostEfficiency(vulns: Vulnerability[]): string[] {
  return [...vulns]
    .sort((a, b) => {
      const effA = a.exploitProbability * a.cvssScore / Math.max(a.remediationCost, 0.1)
      const effB = b.exploitProbability * b.cvssScore / Math.max(b.remediationCost, 0.1)
      return effB - effA
    })
    .map(v => v.id)
}

function sortByCriticality(vulns: Vulnerability[], graph: AttackGraph): string[] {
  // Prioritize vulns affecting critical-tier services
  const tierScore: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
  const serviceMap = new Map(graph.services.map(s => [s.id, s]))

  return [...vulns]
    .sort((a, b) => {
      const aScore = Math.max(...a.affectedServiceIds.map(id => tierScore[serviceMap.get(id)?.tier ?? 'low'] ?? 0))
      const bScore = Math.max(...b.affectedServiceIds.map(id => tierScore[serviceMap.get(id)?.tier ?? 'low'] ?? 0))
      if (bScore !== aScore) return bScore - aScore
      return b.exploitProbability - a.exploitProbability
    })
    .map(v => v.id)
}

function shuffleArray(arr: string[]): string[] {
  const copy = [...arr]
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[copy[i], copy[j]] = [copy[j], copy[i]]
  }
  return copy
}

/**
 * Remove solutions within 2% risk, 0.5 hrs cost, 2 min downtime of each other.
 */
function deduplicateSolutions(solutions: ParetoSolution[]): ParetoSolution[] {
  const kept: ParetoSolution[] = []
  for (const sol of solutions) {
    const isDupe = kept.some(k =>
      Math.abs(k.totalRisk - sol.totalRisk) < 0.02 &&
      Math.abs(k.totalCost - sol.totalCost) < 0.5 &&
      Math.abs(k.totalDowntime - sol.totalDowntime) < 2
    )
    if (!isDupe) kept.push(sol)
  }
  return kept
}
