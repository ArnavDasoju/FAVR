/**
 * Quick standalone test for the budget optimizer logic.
 * Run with: node test-optimizer.mjs
 *
 * This tests the pure algorithm — no Electron, no IPC.
 */

// Since the optimizer uses TS imports, we'll replicate the core logic inline for testing.
// In a real test suite you'd use vitest/jest with ts-node.

// ─── Mock data ───────────────────────────────────────────────

const mockVulns = [
  { id: 'v1', cveId: 'CVE-2024-0001', severity: 'critical', complexity: 'high', affectedPackage: 'express@4.18.2', patchedVersion: 'express@4.21.0', title: 'RCE in Express', description: '', cvssScore: 9.8, epssScore: 0.7 },
  { id: 'v2', cveId: 'CVE-2024-0002', severity: 'high', complexity: 'medium', affectedPackage: 'axios@1.5.0', patchedVersion: 'axios@1.7.0', title: 'SSRF in Axios', description: '', cvssScore: 7.5, epssScore: 0.4 },
  { id: 'v3', cveId: 'CVE-2024-0003', severity: 'medium', complexity: 'low', affectedPackage: 'lodash@4.17.20', patchedVersion: 'lodash@4.17.21', title: 'Prototype pollution', description: '', cvssScore: 5.3, epssScore: 0.1 },
  { id: 'v4', cveId: 'CVE-2024-0004', severity: 'low', complexity: 'low', affectedPackage: 'debug@4.3.4', patchedVersion: 'debug@4.3.5', title: 'ReDoS', description: '', cvssScore: 3.1, epssScore: 0.05 },
  { id: 'v5', cveId: 'CVE-2024-0005', severity: 'critical', complexity: 'high', affectedPackage: 'jsonwebtoken@9.0.0', patchedVersion: 'jsonwebtoken@9.0.2', title: 'JWT bypass', description: '', cvssScore: 9.1, epssScore: 0.8 },
]

const optimalOrder = ['v5', 'v1', 'v2', 'v3', 'v4'] // Monte Carlo output

const mockModels = [
  { model: 'ollama/llama3', costPer1kTokens: 0, maxComplexity: 'high', taskTypes: [], available: true },
  { model: 'google/gemini-2.5-flash', costPer1kTokens: 0, maxComplexity: 'medium', taskTypes: [], available: true },
  { model: 'deepseek/deepseek-chat', costPer1kTokens: 0.001, maxComplexity: 'high', taskTypes: [], available: true },
  { model: 'anthropic/claude-sonnet-4.6', costPer1kTokens: 0.003, maxComplexity: 'high', taskTypes: [], available: true },
  { model: 'openai/gpt-5.4', costPer1kTokens: 0.005, maxComplexity: 'high', taskTypes: [], available: true },
]

const mockStats = [
  { model: 'ollama/llama3', successRate: 0.50, avgCostPerFix: 0, complexityScores: { low: 0.70, medium: 0.45, high: 0.25 } },
  { model: 'google/gemini-2.5-flash', successRate: 0.60, avgCostPerFix: 0.001, complexityScores: { low: 0.80, medium: 0.58, high: 0.35 } },
  { model: 'deepseek/deepseek-chat', successRate: 0.70, avgCostPerFix: 0.003, complexityScores: { low: 0.85, medium: 0.72, high: 0.50 } },
  { model: 'anthropic/claude-sonnet-4.6', successRate: 0.85, avgCostPerFix: 0.08, complexityScores: { low: 0.95, medium: 0.88, high: 0.75 } },
  { model: 'openai/gpt-5.4', successRate: 0.80, avgCostPerFix: 0.12, complexityScores: { low: 0.92, medium: 0.82, high: 0.70 } },
]

// ─── Replicate scoring logic ─────────────────────────────────

const TOKEN_ESTIMATES = { low: 2000, medium: 8000, high: 20000 }

function estimateCost(model, complexity) {
  const cap = mockModels.find(m => m.model === model)
  if (!cap) return 0
  return (TOKEN_ESTIMATES[complexity] / 1000) * cap.costPer1kTokens
}

function getMinFreeSuccess(vuln) {
  switch (vuln.severity) {
    case 'critical': return 0.65
    case 'high': return 0.55
    case 'medium': return 0.40
    case 'low': return 0.30
    default: return 0.40
  }
}

function scoreModel(stats, complexity, cost) {
  const complexityRate = stats.complexityScores[complexity]
  const overallRate = stats.successRate
  const expectedSuccess = 0.7 * complexityRate + 0.3 * overallRate
  if (cost === 0) return expectedSuccess
  return (expectedSuccess * expectedSuccess) / cost
}

function optimize(vulns, order, budget, preferFree) {
  let remaining = budget
  const assignments = []
  const skipped = []

  for (const vulnId of order) {
    const vuln = vulns.find(v => v.id === vulnId)
    if (!vuln) continue

    let bestCandidate = null

    // Score all models
    const candidates = []
    for (const m of mockModels) {
      if (!m.available) continue
      const cost = estimateCost(m.model, vuln.complexity)
      if (cost > remaining && cost > 0) continue

      const stats = mockStats.find(s => s.model === m.model)
      if (!stats) continue

      const expectedSuccess = 0.7 * stats.complexityScores[vuln.complexity] + 0.3 * stats.successRate
      const score = scoreModel(stats, vuln.complexity, cost)
      candidates.push({ model: m.model, cost, expectedSuccess, score })
    }

    if (preferFree) {
      const freeViable = candidates.filter(c => c.cost === 0 && c.expectedSuccess >= getMinFreeSuccess(vuln))
      if (freeViable.length > 0) {
        freeViable.sort((a, b) => b.expectedSuccess - a.expectedSuccess)
        bestCandidate = freeViable[0]
      }
    }

    if (!bestCandidate) {
      candidates.sort((a, b) => b.score - a.score)
      bestCandidate = candidates[0]
    }

    if (!bestCandidate) {
      skipped.push({ vulnId: vuln.id, cveId: vuln.cveId, reason: 'over-budget' })
      continue
    }

    remaining -= bestCandidate.cost
    assignments.push({
      vulnId: vuln.id,
      cveId: vuln.cveId,
      severity: vuln.severity,
      complexity: vuln.complexity,
      model: bestCandidate.model,
      cost: bestCandidate.cost,
      expectedSuccess: bestCandidate.expectedSuccess
    })
  }

  return { assignments, skipped, totalCost: budget - remaining, remaining }
}

// ─── Run tests ───────────────────────────────────────────────

console.log('=== Test 1: $0 budget (free models only) ===')
const r1 = optimize(mockVulns, optimalOrder, 0, true)
console.log(`  Assigned: ${r1.assignments.length}, Skipped: ${r1.skipped.length}`)
for (const a of r1.assignments) {
  console.log(`  ${a.cveId} (${a.severity}/${a.complexity}) → ${a.model} ($${a.cost.toFixed(4)}, ${(a.expectedSuccess * 100).toFixed(0)}%)`)
}
for (const s of r1.skipped) {
  console.log(`  SKIPPED: ${s.cveId} — ${s.reason}`)
}
const allFree1 = r1.assignments.every(a => a.cost === 0)
console.log(`  All free? ${allFree1 ? 'PASS' : 'FAIL'}`)
console.log(`  Total cost: $${r1.totalCost.toFixed(4)}`)
console.log()

console.log('=== Test 2: $0.50 budget (mixed) ===')
const r2 = optimize(mockVulns, optimalOrder, 0.50, true)
console.log(`  Assigned: ${r2.assignments.length}, Skipped: ${r2.skipped.length}`)
for (const a of r2.assignments) {
  console.log(`  ${a.cveId} (${a.severity}/${a.complexity}) → ${a.model} ($${a.cost.toFixed(4)}, ${(a.expectedSuccess * 100).toFixed(0)}%)`)
}
const underBudget2 = r2.totalCost <= 0.50
console.log(`  Under budget? ${underBudget2 ? 'PASS' : 'FAIL'} ($${r2.totalCost.toFixed(4)} / $0.50)`)
console.log()

console.log('=== Test 3: $50 budget, preferFree=false (best models) ===')
const r3 = optimize(mockVulns, optimalOrder, 50, false)
console.log(`  Assigned: ${r3.assignments.length}, Skipped: ${r3.skipped.length}`)
for (const a of r3.assignments) {
  console.log(`  ${a.cveId} (${a.severity}/${a.complexity}) → ${a.model} ($${a.cost.toFixed(4)}, ${(a.expectedSuccess * 100).toFixed(0)}%)`)
}
const noSkips3 = r3.skipped.length === 0
console.log(`  No skips? ${noSkips3 ? 'PASS' : 'FAIL'}`)
// Critical vulns should get expensive models when budget is generous
const criticals = r3.assignments.filter(a => a.severity === 'critical')
const criticalsGetGoodModels = criticals.every(a => a.model.includes('claude') || a.model.includes('deepseek') || a.model.includes('gpt'))
console.log(`  Criticals get capable models? ${criticalsGetGoodModels ? 'PASS' : 'FAIL'}`)
console.log()

console.log('=== Test 4: Budget too small for any paid model ===')
const r4 = optimize(mockVulns, optimalOrder, 0.0001, true)
console.log(`  Assigned: ${r4.assignments.length}, Skipped: ${r4.skipped.length}`)
const allFree4 = r4.assignments.every(a => a.cost === 0)
console.log(`  All free or skipped? ${allFree4 ? 'PASS' : 'FAIL'}`)
console.log()

// Summary
const tests = [allFree1, underBudget2, noSkips3, criticalsGetGoodModels, allFree4]
const passed = tests.filter(Boolean).length
console.log(`=== RESULTS: ${passed}/${tests.length} passed ===`)
process.exit(passed === tests.length ? 0 : 1)
