/**
 * FAVR Analysis Engine — orchestrates the full pipeline:
 * Attack Graph → Bayesian Propagation → Monte Carlo → Pareto Frontier
 * → Blast Radius → Scheduling → Compliance
 */

import type { Service, Dependency, Vulnerability, AnalysisResult, ProgressCallback } from './types'
import { buildAttackGraph, computeTotalRisk } from './attack-graph'
import { propagateRisk } from './bayesian'
import { runMonteCarlo } from './monte-carlo'
import { findParetoFrontier } from './pareto'
import { computeAllBlastRadii } from './blast-radius'
import { buildSchedule } from './scheduler'
import { computeComplianceSummary } from './compliance'
import { fetchEpssScores, estimateEpssFromCvss } from './epss'

const ENGINE_VERSION = '2.1.0'

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
  const iterations = input.iterations ?? 500

  // Phase 0: Enrich with real EPSS data from FIRST.org
  onProgress?.({ phase: 'graph', progress: 0, message: 'Fetching real EPSS scores from FIRST.org...' })

  const cveIds = vulnerabilities.filter(v => v.cveId.startsWith('CVE-')).map(v => v.cveId)
  let epssSource = 'estimated'
  if (cveIds.length > 0) {
    try {
      const epssScores = await fetchEpssScores(cveIds)
      let enriched = 0
      for (const vuln of vulnerabilities) {
        const epss = epssScores.get(vuln.cveId)
        if (epss) {
          vuln.epssScore = epss.epss
          enriched++
        } else if (vuln.epssScore === 0 || vuln.epssScore === undefined) {
          // Only estimate if no EPSS was provided in the input data
          vuln.epssScore = estimateEpssFromCvss(vuln.cvssScore, vuln.knownExploit)
        }
      }
      if (enriched > 0) {
        epssSource = 'live'
        onProgress?.({ phase: 'graph', progress: 20, message: `Enriched ${enriched}/${cveIds.length} CVEs with live EPSS data` })
      } else {
        onProgress?.({ phase: 'graph', progress: 20, message: 'No EPSS matches found, using estimates' })
      }
    } catch {
      onProgress?.({ phase: 'graph', progress: 20, message: 'EPSS API unavailable, using estimates' })
      // Fill in estimates for any missing EPSS scores
      for (const vuln of vulnerabilities) {
        if (!vuln.epssScore) {
          vuln.epssScore = estimateEpssFromCvss(vuln.cvssScore, vuln.knownExploit)
        }
      }
    }
  }

  // Phase 1: Build Attack Graph
  onProgress?.({ phase: 'graph', progress: 30, message: 'Building attack graph...' })

  const graph = buildAttackGraph(services, dependencies, vulnerabilities)

  onProgress?.({ phase: 'graph', progress: 100, message: `Graph built: ${services.length} services, ${dependencies.length} deps, ${vulnerabilities.length} vulns (EPSS: ${epssSource})` })

  // Phase 2: Bayesian Risk Propagation (now with EPSS + compliance weighting)
  onProgress?.({ phase: 'bayesian', progress: 0, message: 'Propagating risk with EPSS + compliance weighting...' })

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

  // Phase 5: Blast Radius Analysis
  onProgress?.({ phase: 'blast-radius', progress: 0, message: 'Computing blast radius for each vulnerability...' })

  const blastRadii = computeAllBlastRadii(graph)

  onProgress?.({
    phase: 'blast-radius',
    progress: 100,
    message: `Blast radius computed for ${Object.keys(blastRadii).length} vulnerabilities`
  })

  // Phase 6: Maintenance Schedule
  onProgress?.({ phase: 'scheduling', progress: 0, message: 'Building maintenance-window-aware schedule...' })

  const schedule = buildSchedule(graph, simulation.optimalOrder)

  const maxWeek = schedule.length > 0 ? Math.max(...schedule.map(s => s.weekNumber)) : 0
  onProgress?.({
    phase: 'scheduling',
    progress: 100,
    message: `Schedule built: ${schedule.length} patches across ${maxWeek} weeks`
  })

  // Phase 7: Compliance Analysis
  onProgress?.({ phase: 'compliance', progress: 0, message: 'Analyzing compliance impact...' })

  const complianceSummary = computeComplianceSummary(graph)

  onProgress?.({
    phase: 'compliance',
    progress: 100,
    message: `${complianceSummary.frameworks.length} frameworks, ${complianceSummary.violations.length} with violations`
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
    blastRadii,
    schedule,
    complianceSummary,
    timestamp: Date.now(),
    engineVersion: ENGINE_VERSION
  }
}

// Re-export types for convenience
export type { AnalysisResult, AnalysisProgress, ProgressCallback } from './types'
export type {
  Service, Dependency, Vulnerability, Severity,
  SimulationResult, ParetoSolution, ParetoFrontier,
  AttackGraph, ConfidenceInterval, VulnConstraint,
  BlastRadius, ScheduledPatch, WhatIfConstraints, WhatIfResult,
  ComplianceFramework, MaintenanceWindow
} from './types'
export { runWhatIf } from './what-if'
export { generateReport } from './report'
