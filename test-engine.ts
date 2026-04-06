/**
 * Standalone test for FAVR math engine.
 * Run: npx tsx test-engine.ts
 */

import { runAnalysis } from './src/main/engine/index'
import { loadMeridianScenario } from './src/main/data/meridian-scenario'

async function main() {
  console.log('=== FAVR Engine Test ===\n')

  const scenario = loadMeridianScenario()
  console.log(`Company: ${scenario.company.name}`)
  console.log(`Services: ${scenario.services.length}`)
  console.log(`Dependencies: ${scenario.dependencies.length}`)
  console.log(`Vulnerabilities: ${scenario.vulnerabilities.length}`)
  console.log()

  const startTime = Date.now()

  const result = await runAnalysis({
    services: scenario.services,
    dependencies: scenario.dependencies,
    vulnerabilities: scenario.vulnerabilities,
    iterations: 1000, // Use 1000 for quick test
    onProgress: (p) => {
      if (p.progress === 0 || p.progress === 100) {
        console.log(`[${p.phase}] ${p.message}`)
      }
    }
  })

  const elapsed = Date.now() - startTime
  console.log(`\nCompleted in ${elapsed}ms\n`)

  // ─── Risk Scores ────────────────────────────────────────────
  console.log('=== Bayesian Risk Scores (after propagation) ===')
  for (const service of result.graph.services) {
    const score = result.riskScores[service.id]
    const bar = '█'.repeat(Math.round(score * 20)) + '░'.repeat(20 - Math.round(score * 20))
    console.log(`  ${service.name.padEnd(20)} ${bar} ${(score * 100).toFixed(1)}%  [${service.tier}]`)
  }

  // ─── Monte Carlo Results ────────────────────────────────────
  console.log('\n=== Monte Carlo Optimal Ordering ===')
  const vulnMap = new Map(result.graph.vulnerabilities.map(v => [v.id, v]))
  for (let i = 0; i < result.simulation.optimalOrder.length; i++) {
    const vulnId = result.simulation.optimalOrder[i]
    const vuln = vulnMap.get(vulnId)!
    const ci = result.simulation.confidenceIntervals[i]
    console.log(`  #${i + 1}. ${vuln.cveId} (${vuln.severity.toUpperCase()}) — ${vuln.title}`)
    console.log(`      Confidence: ${(ci.frequency * 100).toFixed(0)}% | Service: ${vuln.affectedServiceIds.join(', ')}`)
  }

  console.log('\n=== Naive Ordering (severity sort) ===')
  for (let i = 0; i < result.simulation.naiveOrder.length; i++) {
    const vulnId = result.simulation.naiveOrder[i]
    const vuln = vulnMap.get(vulnId)!
    console.log(`  #${i + 1}. ${vuln.cveId} (${vuln.severity.toUpperCase()}) CVSS=${vuln.cvssScore}`)
  }

  // ─── Risk Reduction Curves ──────────────────────────────────
  console.log('\n=== Risk Reduction Curves ===')
  console.log('  Patches  |  Optimal  |  Naive  |  Savings')
  console.log('  ─────────|───────────|─────────|──────────')
  for (let i = 0; i < result.simulation.optimalCurve.length; i++) {
    const opt = result.simulation.optimalCurve[i]
    const naive = result.simulation.naiveCurve[i]
    const savings = naive - opt
    console.log(`  ${String(i).padStart(7)}  |  ${(opt * 100).toFixed(1).padStart(6)}%  |  ${(naive * 100).toFixed(1).padStart(5)}%  |  ${savings > 0 ? '+' : ''}${(savings * 100).toFixed(1)}%`)
  }

  // ─── Verify: optimal should always be ≤ naive ───────────────
  console.log('\n=== Verification ===')
  let allBetter = true
  for (let i = 1; i < result.simulation.optimalCurve.length; i++) {
    if (result.simulation.optimalCurve[i] > result.simulation.naiveCurve[i] + 0.001) {
      console.log(`  FAIL: At step ${i}, optimal (${result.simulation.optimalCurve[i].toFixed(3)}) > naive (${result.simulation.naiveCurve[i].toFixed(3)})`)
      allBetter = false
    }
  }
  if (allBetter) {
    console.log('  PASS: Optimal curve is always ≤ naive curve')
  }

  console.log(`  Risk before: ${(result.simulation.totalRiskBefore * 100).toFixed(1)}%`)
  console.log(`  Risk after:  ${(result.simulation.totalRiskAfter * 100).toFixed(1)}%`)
  console.log(`  Reduction:   ${result.simulation.riskReduction.toFixed(1)}%`)
  console.log(`  Convergence: ${(result.simulation.convergenceScore * 100).toFixed(0)}%`)

  // ─── Pareto Frontier ────────────────────────────────────────
  console.log('\n=== Pareto Frontier ===')
  console.log(`  Total candidates: ${result.pareto.solutions.length}`)
  console.log(`  Frontier size: ${result.pareto.frontierIds.length}`)
  console.log()

  const frontier = result.pareto.solutions.filter(s => !s.dominated)
  console.log('  Label                          |  Risk   |  Cost (hrs) |  Downtime (min)')
  console.log('  ───────────────────────────────|─────────|─────────────|─────────────────')
  for (const sol of frontier) {
    const label = (sol.label ?? sol.id).padEnd(31)
    console.log(`  ${label}|  ${(sol.totalRisk * 100).toFixed(1).padStart(5)}%  |  ${String(sol.totalCost).padStart(8)}    |  ${String(sol.totalDowntime).padStart(12)}`)
  }

  console.log('\n=== Test Complete ===')
}

main().catch(console.error)
