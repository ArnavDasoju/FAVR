/**
 * Budget-Aware Agent Optimizer
 *
 * Given a set of vulnerabilities (in Monte Carlo optimal order), a budget cap,
 * and per-model performance stats, produces an optimal mapping of
 * {vulnerability → model} that maximizes expected fix success while staying
 * under budget.
 *
 * Algorithm: greedy knapsack — iterate vulns in priority order, for each pick
 * the model with the best score-per-dollar that fits the remaining budget.
 * For free models, score is just the expected success rate.
 */

import type { Vulnerability } from '../engine/types'
import type { AgentStats } from './agent-stats'
import { type ModelCapability } from './router'

// ─── Public Interfaces ───────────────────────────────────────

export interface BudgetConstraints {
  maxBudget: number             // total $ cap (0 = free models only)
  maxConcurrentAgents: number   // how many agents can run at once (default 3)
  preferFree: boolean           // always try free models first (default true)
}

export interface AgentAssignment {
  vulnId: string
  cveId: string
  severity: string
  complexity: 'low' | 'medium' | 'high'
  assignedModel: string
  estimatedCost: number
  expectedSuccessRate: number
  reasoning: string
}

export interface OptimizationResult {
  assignments: AgentAssignment[]
  totalEstimatedCost: number
  totalBudget: number
  expectedFixRate: number       // fraction of assigned vulns expected to succeed
  skippedVulns: SkippedVuln[]
  savingsVsNaive: number        // $ saved vs using most expensive model for everything
}

export interface SkippedVuln {
  vulnId: string
  cveId: string
  reason: 'over-budget' | 'no-capable-model'
}

// ─── Token/cost estimation ───────────────────────────────────

const TOKEN_ESTIMATES: Record<string, number> = {
  low: 2000,
  medium: 8000,
  high: 20000
}

function estimateCost(model: string, complexity: 'low' | 'medium' | 'high', models: ModelCapability[]): number {
  const cap = models.find(m => m.model === model)
  if (!cap) return 0
  const tokens = TOKEN_ESTIMATES[complexity] ?? 8000
  return (tokens / 1000) * cap.costPer1kTokens
}

// ─── Scoring ─────────────────────────────────────────────────

/**
 * Score a model for a given vulnerability.
 * Higher = better fit. Factors in:
 * - Success rate at this complexity level
 * - Overall success rate
 * - Cost efficiency (success per dollar, capped for free models)
 */
function scoreModel(
  stats: AgentStats,
  complexity: 'low' | 'medium' | 'high',
  cost: number
): number {
  const complexityRate = stats.complexityScores[complexity]
  const overallRate = stats.successRate

  // Weighted blend: complexity-specific rate matters more
  const expectedSuccess = 0.7 * complexityRate + 0.3 * overallRate

  if (cost === 0) {
    // Free model — score is just expected success (no cost penalty)
    return expectedSuccess
  }

  // Paid model — score balances success and cost.
  // We want high success AND low cost, so: success^2 / cost
  // The square emphasizes that a model with 0.9 success at $0.10
  // is much better than 0.5 success at $0.01
  return (expectedSuccess * expectedSuccess) / cost
}

// ─── Main Optimizer ──────────────────────────────────────────

/**
 * Produce optimal {vuln → model} assignments under budget constraints.
 *
 * @param vulns        All vulnerabilities from the analysis
 * @param optimalOrder Vuln IDs in Monte Carlo optimal patch order
 * @param constraints  Budget and concurrency constraints
 * @param stats        Per-model performance stats (from AgentStatsTracker)
 * @param models       Available models with pricing (from ModelRouter)
 */
export function optimizeAgentAssignments(
  vulns: Vulnerability[],
  optimalOrder: string[],
  constraints: BudgetConstraints,
  stats: AgentStats[],
  models: ModelCapability[]
): OptimizationResult {
  const { maxBudget, preferFree } = constraints
  const vulnMap = new Map(vulns.map(v => [v.id, v]))
  const statsMap = new Map(stats.map(s => [s.model, s]))
  const availableModels = models.filter(m => m.available)

  let remainingBudget = maxBudget
  const assignments: AgentAssignment[] = []
  const skippedVulns: SkippedVuln[] = []

  // Walk vulns in priority order
  for (const vulnId of optimalOrder) {
    const vuln = vulnMap.get(vulnId)
    if (!vuln) continue

    const candidate = pickBestModel(
      vuln,
      availableModels,
      statsMap,
      remainingBudget,
      preferFree
    )

    if (!candidate) {
      skippedVulns.push({
        vulnId: vuln.id,
        cveId: vuln.cveId,
        reason: remainingBudget <= 0 ? 'over-budget' : 'no-capable-model'
      })
      continue
    }

    remainingBudget -= candidate.estimatedCost
    assignments.push({
      vulnId: vuln.id,
      cveId: vuln.cveId,
      severity: vuln.severity,
      complexity: vuln.complexity,
      assignedModel: candidate.model,
      estimatedCost: candidate.estimatedCost,
      expectedSuccessRate: candidate.expectedSuccess,
      reasoning: candidate.reasoning
    })
  }

  const totalEstimatedCost = assignments.reduce((sum, a) => sum + a.estimatedCost, 0)

  // Compute savings vs naive (most expensive model for everything)
  const mostExpensiveModel = availableModels.reduce(
    (max, m) => m.costPer1kTokens > max.costPer1kTokens ? m : max,
    availableModels[0]
  )
  const naiveCost = optimalOrder.reduce((sum, vid) => {
    const v = vulnMap.get(vid)
    if (!v || !mostExpensiveModel) return sum
    return sum + estimateCost(mostExpensiveModel.model, v.complexity, models)
  }, 0)

  // Expected fix rate: weighted average of success rates
  const expectedFixRate = assignments.length > 0
    ? assignments.reduce((sum, a) => sum + a.expectedSuccessRate, 0) / assignments.length
    : 0

  return {
    assignments,
    totalEstimatedCost,
    totalBudget: maxBudget,
    expectedFixRate,
    skippedVulns,
    savingsVsNaive: naiveCost - totalEstimatedCost
  }
}

// ─── Model Selection ─────────────────────────────────────────

interface ModelCandidate {
  model: string
  estimatedCost: number
  expectedSuccess: number
  score: number
  reasoning: string
}

function pickBestModel(
  vuln: Vulnerability,
  availableModels: ModelCapability[],
  statsMap: Map<string, AgentStats>,
  remainingBudget: number,
  preferFree: boolean
): ModelCandidate | null {
  const candidates: ModelCandidate[] = []

  for (const m of availableModels) {
    const cost = estimateCost(m.model, vuln.complexity, availableModels)

    // Skip if over budget (free models always fit)
    if (cost > remainingBudget && cost > 0) continue

    const modelStats = statsMap.get(m.model)
    if (!modelStats) continue

    const expectedSuccess = 0.7 * modelStats.complexityScores[vuln.complexity] + 0.3 * modelStats.successRate
    const score = scoreModel(modelStats, vuln.complexity, cost)

    let reasoning: string
    if (cost === 0) {
      reasoning = `Free model with ${(expectedSuccess * 100).toFixed(0)}% expected success for ${vuln.complexity} complexity`
    } else {
      reasoning = `$${cost.toFixed(4)} estimated, ${(expectedSuccess * 100).toFixed(0)}% expected success for ${vuln.complexity} complexity`
    }

    candidates.push({ model: m.model, estimatedCost: cost, expectedSuccess, score, reasoning })
  }

  if (candidates.length === 0) return null

  if (preferFree) {
    // Check if any free model has a reasonable success rate for this complexity
    const freeModels = candidates.filter(c => c.estimatedCost === 0)
    const MINIMUM_FREE_SUCCESS = getMinFreeSuccess(vuln)

    const viableFree = freeModels.filter(c => c.expectedSuccess >= MINIMUM_FREE_SUCCESS)
    if (viableFree.length > 0) {
      // Pick the free model with highest expected success
      viableFree.sort((a, b) => b.expectedSuccess - a.expectedSuccess)
      const pick = viableFree[0]
      pick.reasoning = `Free-first: ${pick.reasoning}`
      return pick
    }
  }

  // Pick model with highest score (best success-per-dollar)
  candidates.sort((a, b) => b.score - a.score)
  return candidates[0]
}

/**
 * Minimum success rate threshold for free models.
 * Higher-severity vulns demand more capable models — we don't want to
 * waste a free attempt on a critical vuln if the model is likely to fail.
 */
function getMinFreeSuccess(vuln: Vulnerability): number {
  switch (vuln.severity) {
    case 'critical': return 0.65
    case 'high': return 0.55
    case 'medium': return 0.40
    case 'low': return 0.30
    default: return 0.40
  }
}
