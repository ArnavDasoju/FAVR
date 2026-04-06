/**
 * FAVR Analysis Engine — orchestrates the full pipeline:
 * Attack Graph → Bayesian Propagation → Monte Carlo → Pareto Frontier
 */

import type { Service, Dependency, Vulnerability, AnalysisResult, ProgressCallback } from './types'
import { buildAttackGraph, computeTotalRisk } from './attack-graph'
import { propagateRisk } from './bayesian'
import { runMonteCarlo } from './monte-carlo'
import { findParetoFrontier } from './pareto'

const ENGINE_VERSION = '1.0.0'

/**
 * Run the complete FAVR analysis pipeline.
 */
export async function runAnalysis(input: {
  services: Service[]
  dependencies: Dependency[]
  vulnerabilities: Vulnerability[]
  iterations?: number
  onProgress?: ProgressCallback
}): Promise<AnalysisResult> {
  const { services, dependencies, vulnerabilities, onProgress } = input
  const iterations = input.iterations ?? 10000

  // Phase 1: Build Attack Graph
  onProgress?.({ phase: 'graph', progress: 0, message: 'Building attack graph...' })

  const graph = buildAttackGraph(services, dependencies, vulnerabilities)

  onProgress?.({ phase: 'graph', progress: 100, message: `Graph built: ${services.length} services, ${dependencies.length} dependencies, ${vulnerabilities.length} vulnerabilities` })

  // Phase 2: Bayesian Risk Propagation
  onProgress?.({ phase: 'bayesian', progress: 0, message: 'Propagating risk through dependency graph...' })

  const riskScores = propagateRisk(graph)

  const riskScoreObj: Record<string, number> = {}
  for (const [id, score] of riskScores) {
    riskScoreObj[id] = score
  }

  onProgress?.({ phase: 'bayesian', progress: 100, message: `Risk propagation complete. Total system risk: ${(computeTotalRisk(services) * 100).toFixed(1)}%` })

  // Phase 3: Monte Carlo Simulation
  onProgress?.({ phase: 'monte-carlo', progress: 0, message: `Running ${iterations.toLocaleString()} Monte Carlo simulations...` })

  const simulation = runMonteCarlo(graph, iterations, (pct) => {
    onProgress?.({
      phase: 'monte-carlo',
      progress: pct,
      message: `Simulating patch orderings... ${pct}%`
    })
  })

  onProgress?.({
    phase: 'monte-carlo',
    progress: 100,
    message: `Simulation complete. Risk reduction: ${simulation.riskReduction.toFixed(1)}%. Convergence: ${(simulation.convergenceScore * 100).toFixed(0)}%`
  })

  // Phase 4: Pareto Optimization
  onProgress?.({ phase: 'pareto', progress: 0, message: 'Computing Pareto frontier...' })

  const pareto = findParetoFrontier(graph, simulation.optimalOrder, simulation.naiveOrder)

  onProgress?.({
    phase: 'pareto',
    progress: 100,
    message: `Found ${pareto.frontierIds.length} Pareto-optimal solutions from ${pareto.solutions.length} candidates`
  })

  // Complete
  onProgress?.({ phase: 'complete', progress: 100, message: 'Analysis complete.' })

  return {
    graph: {
      services: graph.services,
      dependencies: graph.dependencies,
      vulnerabilities: graph.vulnerabilities
    },
    riskScores: riskScoreObj,
    simulation,
    pareto,
    timestamp: Date.now(),
    engineVersion: ENGINE_VERSION
  }
}

// Re-export types for convenience
export type { AnalysisResult, AnalysisProgress, ProgressCallback } from './types'
export type {
  Service, Dependency, Vulnerability, Severity,
  SimulationResult, ParetoSolution, ParetoFrontier,
  AttackGraph, ConfidenceInterval, VulnConstraint
} from './types'
