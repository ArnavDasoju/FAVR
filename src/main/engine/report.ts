/**
 * Report Generator — produces a ranked upgrade plan as HTML.
 *
 * The deliverable a security team hands to their CISO:
 * - Executive summary
 * - Ranked patch order with justification
 * - Compliance impact
 * - Maintenance schedule
 * - Risk metrics
 */

import type { AnalysisResult, Vulnerability, Service, BlastRadius, ScheduledPatch } from './types'

export function generateReport(result: AnalysisResult): string {
  const { graph, simulation, pareto, blastRadii, schedule, complianceSummary, riskScores } = result
  const vulnMap = new Map(graph.vulnerabilities.map(v => [v.id, v]))
  const serviceMap = new Map(graph.services.map(s => [s.id, s]))

  const totalRiskBefore = Math.round(simulation.totalRiskBefore * 100)
  const totalRiskAfter = Math.round(simulation.totalRiskAfter * 100)
  const reduction = Math.round(simulation.riskReduction)
  const totalCost = graph.vulnerabilities.filter(v => v.status === 'open').reduce((s, v) => s + v.remediationCost, 0)
  const totalDowntime = graph.vulnerabilities.filter(v => v.status === 'open').reduce((s, v) => s + v.remediationDowntime, 0)
  const criticalCount = graph.vulnerabilities.filter(v => v.severity === 'critical' && v.status === 'open').length
  const maxWeek = schedule.length > 0 ? Math.max(...schedule.map(s => s.weekNumber)) : 0

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FAVR Vulnerability Remediation Plan</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, sans-serif; background: #0a0a0a; color: #fafafa; padding: 40px; line-height: 1.6; }
  .container { max-width: 900px; margin: 0 auto; }
  h1 { font-size: 28px; font-weight: 900; margin-bottom: 4px; }
  h2 { font-size: 18px; font-weight: 700; margin: 32px 0 16px; border-bottom: 1px solid #333; padding-bottom: 8px; }
  h3 { font-size: 14px; font-weight: 700; margin: 20px 0 8px; }
  .subtitle { color: #a3a3a3; font-size: 13px; margin-bottom: 24px; }
  .timestamp { color: #525252; font-size: 11px; margin-bottom: 32px; }
  .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-card { background: #171717; border: 1px solid #262626; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-value { font-size: 24px; font-weight: 900; }
  .stat-label { font-size: 10px; color: #737373; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; margin-top: 4px; }
  .red { color: #ef4444; } .green { color: #22c55e; } .amber { color: #f59e0b; } .blue { color: #3b82f6; } .white { color: #fff; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; }
  th { text-align: left; font-size: 10px; color: #737373; text-transform: uppercase; font-weight: 700; padding: 8px 12px; border-bottom: 1px solid #333; }
  td { padding: 10px 12px; border-bottom: 1px solid #1a1a1a; font-size: 13px; }
  tr:hover { background: #111; }
  .badge { display: inline-block; font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; }
  .badge-critical { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); }
  .badge-high { background: rgba(249,115,22,0.15); color: #f97316; border: 1px solid rgba(249,115,22,0.3); }
  .badge-medium { background: rgba(234,179,8,0.15); color: #eab308; border: 1px solid rgba(234,179,8,0.3); }
  .badge-low { background: rgba(59,130,246,0.15); color: #3b82f6; border: 1px solid rgba(59,130,246,0.3); }
  .badge-compliance { background: rgba(168,85,247,0.15); color: #a855f7; border: 1px solid rgba(168,85,247,0.3); }
  .mono { font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  .section { background: #171717; border: 1px solid #262626; border-radius: 8px; padding: 20px; margin: 16px 0; }
  .epss-divergence { display: inline-block; font-size: 10px; padding: 1px 6px; border-radius: 3px; margin-left: 4px; }
  .epss-high { background: rgba(239,68,68,0.2); color: #ef4444; }
  .epss-low { background: rgba(34,197,94,0.2); color: #22c55e; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #262626; color: #525252; font-size: 11px; }
  @media print { body { background: white; color: black; } .stat-card { border-color: #ddd; } }
</style>
</head>
<body>
<div class="container">
  <h1>FAVR Vulnerability Remediation Plan</h1>
  <p class="subtitle">Ranked Upgrade Plan &middot; Attack Graph Analysis &middot; Monte Carlo Optimization</p>
  <p class="timestamp">Generated: ${new Date(result.timestamp).toLocaleString()} &middot; Engine v${result.engineVersion} &middot; ${simulation.iterations.toLocaleString()} MC iterations</p>

  <h2>Executive Summary</h2>
  <div class="stats-grid">
    <div class="stat-card"><div class="stat-value red">${totalRiskBefore}%</div><div class="stat-label">Current Risk</div></div>
    <div class="stat-card"><div class="stat-value green">${totalRiskAfter}%</div><div class="stat-label">After Remediation</div></div>
    <div class="stat-card"><div class="stat-value green">-${reduction}%</div><div class="stat-label">Risk Reduction</div></div>
    <div class="stat-card"><div class="stat-value amber">${totalCost}h</div><div class="stat-label">Total Effort</div></div>
    <div class="stat-card"><div class="stat-value blue">${maxWeek} wk</div><div class="stat-label">Schedule Length</div></div>
  </div>

  <div class="section">
    <p style="font-size:13px; color:#d4d4d4;">
      This analysis identified <strong>${graph.vulnerabilities.filter(v => v.status === 'open').length} open vulnerabilities</strong>
      across <strong>${graph.services.length} services</strong> with <strong>${graph.dependencies.length} dependency relationships</strong>.
      <strong>${criticalCount} critical</strong> vulnerabilities require immediate attention.
      ${complianceSummary.violations.filter(v => v.urgentCount > 0).length > 0
        ? `<span class="red"><strong>${complianceSummary.violations.reduce((s, v) => s + v.urgentCount, 0)} compliance deadlines within 14 days.</strong></span>`
        : 'No urgent compliance deadlines.'}
    </p>
  </div>

${complianceSummary.violations.length > 0 ? `
  <h2>Compliance Impact</h2>
  <table>
    <thead><tr><th>Framework</th><th>Open Violations</th><th>Urgent (&lt;14 days)</th><th>Affected CVEs</th></tr></thead>
    <tbody>
${complianceSummary.violations.map(v => `      <tr>
        <td><span class="badge badge-compliance">${v.framework}</span></td>
        <td>${v.vulnIds.length}</td>
        <td class="${v.urgentCount > 0 ? 'red' : ''}">${v.urgentCount}</td>
        <td class="mono" style="font-size:11px; color:#a3a3a3;">${v.vulnIds.slice(0, 3).map(id => vulnMap.get(id)?.cveId ?? id).join(', ')}${v.vulnIds.length > 3 ? ` +${v.vulnIds.length - 3} more` : ''}</td>
      </tr>`).join('\n')}
    </tbody>
  </table>
` : ''}

  <h2>Ranked Patch Order (FAVR Optimized)</h2>
  <p style="font-size:12px; color:#737373; margin-bottom:12px;">Priority determined by Bayesian risk propagation, EPSS scoring, compliance urgency, and Monte Carlo simulation (${simulation.iterations.toLocaleString()} iterations, ${Math.round(simulation.convergenceScore * 100)}% convergence).</p>

  <table>
    <thead><tr><th>#</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Services</th><th>Cost</th><th>Downtime</th><th>Compliance</th><th>Confidence</th></tr></thead>
    <tbody>
${simulation.optimalOrder.map((vulnId, i) => {
  const vuln = vulnMap.get(vulnId)
  if (!vuln) return ''
  const ci = simulation.confidenceIntervals[i]
  const services = vuln.affectedServiceIds.map(sid => serviceMap.get(sid)?.name ?? sid).join(', ')
  const epssDiv = Math.abs(vuln.epssScore - vuln.cvssScore / 10)
  const epssClass = vuln.epssScore > vuln.cvssScore / 10 ? 'epss-high' : epssDiv > 0.2 ? 'epss-low' : ''
  const epssLabel = vuln.epssScore > vuln.cvssScore / 10 ? 'HIGHER RISK' : epssDiv > 0.2 ? 'LOWER RISK' : ''
  return `      <tr>
        <td style="font-weight:900;">${i + 1}</td>
        <td><strong>${vuln.cveId}</strong><br><span style="font-size:11px;color:#737373;">${vuln.title}</span></td>
        <td><span class="badge badge-${vuln.severity}">${vuln.severity}</span></td>
        <td class="mono">${vuln.cvssScore.toFixed(1)}</td>
        <td class="mono">${(vuln.epssScore * 100).toFixed(0)}%${epssLabel ? `<span class="epss-divergence ${epssClass}">${epssLabel}</span>` : ''}</td>
        <td style="font-size:11px;">${services}</td>
        <td>${vuln.remediationCost}h</td>
        <td>${vuln.remediationDowntime}m</td>
        <td style="font-size:10px;">${(vuln.complianceViolations ?? []).map(f => `<span class="badge badge-compliance" style="margin:1px;">${f}</span>`).join(' ') || '<span style="color:#525252;">—</span>'}</td>
        <td class="mono" style="color:${ci && ci.frequency > 0.7 ? '#22c55e' : '#a3a3a3'}">${ci ? Math.round(ci.frequency * 100) + '%' : '—'}</td>
      </tr>`
}).join('\n')}
    </tbody>
  </table>

${schedule.length > 0 ? `
  <h2>Maintenance Schedule</h2>
  <table>
    <thead><tr><th>Week</th><th>Window</th><th>CVE</th><th>Service</th><th>Start</th><th>Duration</th><th>Dependencies</th></tr></thead>
    <tbody>
${schedule.map(s => {
  const vuln = vulnMap.get(s.vulnId)
  const service = serviceMap.get(s.serviceId)
  return `      <tr>
        <td style="font-weight:700;">Week ${s.weekNumber}</td>
        <td>${s.windowDay} ${s.windowStart}-${s.windowEnd}</td>
        <td class="mono">${vuln?.cveId ?? s.vulnId}</td>
        <td>${service?.name ?? s.serviceId}</td>
        <td class="mono">+${s.estimatedStart}m</td>
        <td>${s.estimatedDuration}m</td>
        <td style="font-size:11px;color:#737373;">${s.dependsOn.length > 0 ? s.dependsOn.map(id => vulnMap.get(id)?.cveId ?? id).join(', ') : '—'}</td>
      </tr>`
}).join('\n')}
    </tbody>
  </table>
` : ''}

  <h2>Service Risk Assessment</h2>
  <table>
    <thead><tr><th>Service</th><th>Tier</th><th>Risk Score</th><th>Compliance</th><th>SLA</th><th>Open CVEs</th></tr></thead>
    <tbody>
${graph.services
  .sort((a, b) => (riskScores[b.id] ?? 0) - (riskScores[a.id] ?? 0))
  .map(s => {
    const risk = Math.round((riskScores[s.id] ?? 0) * 100)
    const vulnCount = graph.vulnerabilities.filter(v => v.affectedServiceIds.includes(s.id) && v.status === 'open').length
    return `      <tr>
        <td><strong>${s.name}</strong></td>
        <td><span class="badge badge-${s.tier}">${s.tier}</span></td>
        <td class="mono" style="color:${risk > 70 ? '#ef4444' : risk > 40 ? '#f59e0b' : '#22c55e'}">${risk}%</td>
        <td style="font-size:10px;">${(s.complianceFrameworks ?? []).map(f => `<span class="badge badge-compliance" style="margin:1px;">${f}</span>`).join(' ') || '—'}</td>
        <td class="mono">${s.sla}%</td>
        <td>${vulnCount}</td>
      </tr>`
  }).join('\n')}
    </tbody>
  </table>

  <h2>Methodology</h2>
  <div class="section" style="font-size:12px; color:#a3a3a3;">
    <p><strong>FAVR</strong> (Framework for Autonomous Vulnerability Remediation) uses a four-stage analysis pipeline:</p>
    <ol style="margin:12px 0 0 20px;">
      <li><strong>Attack Graph Construction</strong> — Models services as nodes, dependencies as directed edges, and attaches CVEs to affected services.</li>
      <li><strong>Bayesian Risk Propagation</strong> — Propagates compromise probability through dependency edges using iterative belief propagation. EPSS scores weight real-world exploitability. Compliance frameworks add regulatory multipliers.</li>
      <li><strong>Monte Carlo Simulation</strong> — Runs ${simulation.iterations.toLocaleString()} iterations with perturbed exploit probabilities. Each iteration uses greedy selection to find the patch ordering that maximally reduces total system risk.</li>
      <li><strong>Pareto Multi-Objective Optimization</strong> — Evaluates tradeoffs across risk reduction, cost (person-hours), and downtime to find non-dominated solutions.</li>
    </ol>
  </div>

  <div class="footer">
    <p>FAVR Engine v${result.engineVersion} &middot; ${simulation.iterations.toLocaleString()} Monte Carlo iterations &middot; ${Math.round(simulation.convergenceScore * 100)}% convergence &middot; ${pareto.frontierIds.length} Pareto-optimal solutions</p>
    <p style="margin-top:4px;">This report is auto-generated. Validate findings with your security team before executing patches.</p>
  </div>
</div>
</body>
</html>`
}
