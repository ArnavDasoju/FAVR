/**
 * Report Generator — produces a ranked upgrade plan as HTML.
 *
 * The deliverable a security team hands to their CISO:
 * - Executive summary with risk gauge
 * - Ranked patch order with justification
 * - Compliance impact
 * - Service risk heatmap
 * - Maintenance schedule
 * - Methodology
 */

import type { AnalysisResult, Vulnerability, Service, BlastRadius, ScheduledPatch } from './types'

export function generateReport(result: AnalysisResult): string {
  const { graph, simulation, pareto, blastRadii, schedule, complianceSummary, riskScores } = result
  const vulnMap = new Map(graph.vulnerabilities.map(v => [v.id, v]))
  const serviceMap = new Map(graph.services.map(s => [s.id, s]))

  const totalRiskBefore = Math.round(simulation.totalRiskBefore * 100)
  const totalRiskAfter = Math.round(simulation.totalRiskAfter * 100)
  const reduction = Math.round(simulation.riskReduction)
  const openVulns = graph.vulnerabilities.filter(v => v.status === 'open')
  const totalCost = openVulns.reduce((s, v) => s + v.remediationCost, 0)
  const totalDowntime = openVulns.reduce((s, v) => s + v.remediationDowntime, 0)
  const criticalCount = openVulns.filter(v => v.severity === 'critical').length
  const highCount = openVulns.filter(v => v.severity === 'high').length
  const maxWeek = schedule.length > 0 ? Math.max(...schedule.map(s => s.weekNumber)) : 0
  const urgentCompliance = complianceSummary.violations.reduce((s, v) => s + v.urgentCount, 0)

  const riskGrade = totalRiskBefore > 80 ? 'F' : totalRiskBefore > 60 ? 'D' : totalRiskBefore > 40 ? 'C' : totalRiskBefore > 20 ? 'B' : 'A'
  const riskColor = totalRiskBefore > 70 ? '#ef4444' : totalRiskBefore > 40 ? '#f59e0b' : '#22c55e'

  const date = new Date(result.timestamp)
  const dateStr = date.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })
  const timeStr = date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })

  // SVG risk gauge
  const gaugeSize = 120
  const gaugeStroke = 10
  const gaugeRadius = (gaugeSize - gaugeStroke) / 2
  const gaugeCircumference = 2 * Math.PI * gaugeRadius
  const gaugeDashOffset = gaugeCircumference * (1 - totalRiskBefore / 100)

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FAVR Vulnerability Remediation Plan</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;900&family=JetBrains+Mono:wght@400;500;700&display=swap');

  :root {
    --bg: #09090b;
    --surface: #18181b;
    --surface-hover: #27272a;
    --border: #27272a;
    --border-light: #3f3f46;
    --text: #fafafa;
    --text-muted: #a1a1aa;
    --text-dim: #71717a;
    --text-faint: #52525b;
    --red: #ef4444;
    --orange: #f97316;
    --amber: #f59e0b;
    --green: #22c55e;
    --blue: #3b82f6;
    --purple: #a855f7;
    --indigo: #6366f1;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }

  .page {
    max-width: 960px;
    margin: 0 auto;
    padding: 48px 40px 60px;
  }

  /* ── Header ────────────────────────────────── */
  .header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 40px;
    padding-bottom: 32px;
    border-bottom: 1px solid var(--border);
  }

  .header-left { flex: 1; }

  .logo-row {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 8px;
  }

  .logo-icon {
    width: 32px;
    height: 32px;
    background: #fff;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
    font-size: 14px;
    color: #000;
  }

  .logo-text {
    font-size: 24px;
    font-weight: 900;
    letter-spacing: -0.5px;
  }

  .report-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-muted);
    margin-bottom: 4px;
  }

  .report-meta {
    font-size: 11px;
    color: var(--text-faint);
    font-family: 'JetBrains Mono', monospace;
  }

  .header-right {
    text-align: right;
  }

  .header-date {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
  }

  .header-time {
    font-size: 11px;
    color: var(--text-dim);
    margin-top: 2px;
  }

  /* ── Section headers ───────────────────────── */
  .section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 36px 0 16px;
    padding-bottom: 8px;
    border-bottom: 1px solid var(--border);
  }

  .section-number {
    font-size: 10px;
    font-weight: 700;
    color: var(--text-faint);
    background: var(--surface);
    border: 1px solid var(--border);
    width: 22px;
    height: 22px;
    border-radius: 6px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .section-title {
    font-size: 16px;
    font-weight: 700;
  }

  /* ── Hero stats ────────────────────────────── */
  .hero {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 32px;
    margin-bottom: 28px;
  }

  .gauge-container {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px 28px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }

  .gauge-svg { transform: rotate(-90deg); }

  .gauge-label {
    font-size: 10px;
    font-weight: 700;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-top: 8px;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 12px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
  }

  .stat-icon-row {
    display: flex;
    align-items: center;
    gap: 6px;
    margin-bottom: 8px;
  }

  .stat-icon {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }

  .stat-label {
    font-size: 9px;
    color: var(--text-dim);
    text-transform: uppercase;
    font-weight: 700;
    letter-spacing: 0.08em;
  }

  .stat-value {
    font-size: 22px;
    font-weight: 900;
    line-height: 1.2;
  }

  .stat-sub {
    font-size: 10px;
    color: var(--text-faint);
    margin-top: 2px;
  }

  /* ── Alert banner ──────────────────────────── */
  .alert {
    background: rgba(168,85,247,0.08);
    border: 1px solid rgba(168,85,247,0.25);
    border-radius: 10px;
    padding: 14px 18px;
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 24px;
  }

  .alert-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--purple);
    flex-shrink: 0;
  }

  .alert-text {
    font-size: 13px;
    font-weight: 600;
    color: var(--purple);
  }

  .alert-sub {
    font-size: 11px;
    color: rgba(168,85,247,0.6);
    margin-top: 2px;
  }

  /* ── Summary card ──────────────────────────── */
  .summary-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px 20px;
    margin-bottom: 24px;
    font-size: 13px;
    color: #d4d4d8;
    line-height: 1.7;
  }

  /* ── Tables ────────────────────────────────── */
  .table-wrap {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    margin: 16px 0;
  }

  table {
    width: 100%;
    border-collapse: collapse;
  }

  th {
    text-align: left;
    font-size: 9px;
    color: var(--text-dim);
    text-transform: uppercase;
    font-weight: 700;
    letter-spacing: 0.06em;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    background: rgba(255,255,255,0.02);
  }

  td {
    padding: 11px 14px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    vertical-align: top;
  }

  tr:last-child td { border-bottom: none; }
  tr:hover { background: rgba(255,255,255,0.02); }

  .rank-cell {
    font-weight: 900;
    font-size: 14px;
    color: var(--text);
    width: 36px;
    text-align: center;
  }

  .rank-1 {
    background: rgba(255,255,255,0.05);
  }

  .cve-id {
    font-weight: 700;
    font-size: 13px;
    color: var(--text);
  }

  .cve-title {
    font-size: 11px;
    color: var(--text-dim);
    margin-top: 2px;
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  /* ── Badges ────────────────────────────────── */
  .badge {
    display: inline-block;
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    padding: 2px 7px;
    border-radius: 4px;
    letter-spacing: 0.03em;
  }

  .badge-critical { background: rgba(239,68,68,0.12); color: var(--red); border: 1px solid rgba(239,68,68,0.25); }
  .badge-high { background: rgba(249,115,22,0.12); color: var(--orange); border: 1px solid rgba(249,115,22,0.25); }
  .badge-medium { background: rgba(234,179,8,0.12); color: var(--amber); border: 1px solid rgba(234,179,8,0.25); }
  .badge-low { background: rgba(59,130,246,0.12); color: var(--blue); border: 1px solid rgba(59,130,246,0.25); }
  .badge-compliance { background: rgba(168,85,247,0.12); color: var(--purple); border: 1px solid rgba(168,85,247,0.25); }

  .epss-bar-track {
    display: inline-block;
    width: 40px;
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
    vertical-align: middle;
    margin-right: 4px;
  }

  .epss-bar-fill {
    height: 100%;
    border-radius: 2px;
  }

  .epss-diverge {
    display: inline-block;
    font-size: 9px;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 3px;
    margin-left: 3px;
  }

  .epss-high { background: rgba(239,68,68,0.15); color: var(--red); }
  .epss-low { background: rgba(34,197,94,0.15); color: var(--green); }

  .mono {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
  }

  /* ── Risk bar ──────────────────────────────── */
  .risk-bar-track {
    width: 100%;
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
    margin-top: 4px;
  }

  .risk-bar-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.3s;
  }

  /* ── Service grid ──────────────────────────── */
  .service-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 12px;
    margin: 16px 0;
  }

  .service-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
  }

  .service-name {
    font-size: 13px;
    font-weight: 700;
    margin-bottom: 2px;
  }

  .service-meta {
    font-size: 10px;
    color: var(--text-dim);
  }

  .service-risk {
    font-size: 20px;
    font-weight: 900;
    margin-top: 8px;
  }

  /* ── Methodology ───────────────────────────── */
  .method-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
    margin: 16px 0;
  }

  .method-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
  }

  .method-step {
    font-size: 10px;
    font-weight: 700;
    color: var(--text-faint);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 6px;
  }

  .method-title {
    font-size: 13px;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 4px;
  }

  .method-desc {
    font-size: 11px;
    color: var(--text-dim);
    line-height: 1.5;
  }

  /* ── Footer ────────────────────────────────── */
  .footer {
    margin-top: 48px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .footer-left {
    font-size: 11px;
    color: var(--text-faint);
  }

  .footer-right {
    font-size: 10px;
    color: var(--text-faint);
    font-family: 'JetBrains Mono', monospace;
  }

  .footer-disclaimer {
    font-size: 10px;
    color: var(--text-faint);
    margin-top: 8px;
    line-height: 1.5;
  }

  /* ── Print ─────────────────────────────────── */
  @media print {
    body { background: #fff; color: #111; }
    .page { padding: 20px; }
    .stat-card, .summary-card, .table-wrap, .gauge-container, .service-card, .method-card, .alert {
      border-color: #ddd;
      background: #fafafa;
    }
    th { background: #f5f5f5; }
    .badge { border-color: #ddd; }
  }
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="logo-row">
        <div class="logo-icon">F</div>
        <span class="logo-text">FAVR</span>
      </div>
      <div class="report-title">Vulnerability Remediation Plan</div>
      <div class="report-meta">Engine v${result.engineVersion} &middot; ${simulation.iterations.toLocaleString()} MC iterations &middot; ${Math.round(simulation.convergenceScore * 100)}% convergence</div>
    </div>
    <div class="header-right">
      <div class="header-date">${dateStr}</div>
      <div class="header-time">${timeStr}</div>
    </div>
  </div>

${urgentCompliance > 0 ? `
  <!-- Compliance Alert -->
  <div class="alert">
    <div class="alert-dot"></div>
    <div>
      <div class="alert-text">${urgentCompliance} Compliance Deadline${urgentCompliance !== 1 ? 's' : ''} Within 14 Days</div>
      <div class="alert-sub">${complianceSummary.violations.filter(v => v.urgentCount > 0).map(v => v.framework).join(', ')}</div>
    </div>
  </div>
` : ''}

  <!-- 1. Executive Summary -->
  <div class="section-header">
    <span class="section-number">1</span>
    <span class="section-title">Executive Summary</span>
  </div>

  <div class="hero">
    <div class="gauge-container">
      <svg class="gauge-svg" width="${gaugeSize}" height="${gaugeSize}" viewBox="0 0 ${gaugeSize} ${gaugeSize}">
        <circle cx="${gaugeSize / 2}" cy="${gaugeSize / 2}" r="${gaugeRadius}" fill="none" stroke="${'#27272a'}" stroke-width="${gaugeStroke}" />
        <circle cx="${gaugeSize / 2}" cy="${gaugeSize / 2}" r="${gaugeRadius}" fill="none"
          stroke="${riskColor}" stroke-width="${gaugeStroke}" stroke-linecap="round"
          stroke-dasharray="${gaugeCircumference}" stroke-dashoffset="${gaugeDashOffset}" />
        <text x="${gaugeSize / 2}" y="${gaugeSize / 2 - 6}" text-anchor="middle" fill="#fafafa" font-size="26" font-weight="900" font-family="Inter, sans-serif" transform="rotate(90, ${gaugeSize / 2}, ${gaugeSize / 2})">${totalRiskBefore}%</text>
        <text x="${gaugeSize / 2}" y="${gaugeSize / 2 + 14}" text-anchor="middle" fill="${riskColor}" font-size="10" font-weight="700" font-family="Inter, sans-serif" transform="rotate(90, ${gaugeSize / 2}, ${gaugeSize / 2})">${riskGrade}</text>
      </svg>
      <div class="gauge-label">System Risk</div>
    </div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon-row"><div class="stat-icon" style="background:var(--green)"></div><div class="stat-label">Reduction</div></div>
        <div class="stat-value" style="color:var(--green)">-${reduction}%</div>
        <div class="stat-sub">after full remediation</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-row"><div class="stat-icon" style="background:var(--text)"></div><div class="stat-label">CVEs Found</div></div>
        <div class="stat-value" style="color:var(--text)">${openVulns.length}</div>
        <div class="stat-sub">${criticalCount} critical, ${highCount} high</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-row"><div class="stat-icon" style="background:var(--amber)"></div><div class="stat-label">Total Effort</div></div>
        <div class="stat-value" style="color:var(--amber)">${totalCost}h</div>
        <div class="stat-sub">${totalDowntime}min downtime</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-row"><div class="stat-icon" style="background:var(--blue)"></div><div class="stat-label">Schedule</div></div>
        <div class="stat-value" style="color:var(--blue)">${maxWeek}wk</div>
        <div class="stat-sub">${schedule.length} patches</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-row"><div class="stat-icon" style="background:var(--purple)"></div><div class="stat-label">Frameworks</div></div>
        <div class="stat-value" style="color:var(--purple)">${complianceSummary.frameworks.length}</div>
        <div class="stat-sub">${complianceSummary.violations.length} with violations</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-row"><div class="stat-icon" style="background:var(--indigo)"></div><div class="stat-label">Pareto</div></div>
        <div class="stat-value" style="color:var(--indigo)">${pareto.frontierIds.length}</div>
        <div class="stat-sub">optimal tradeoffs</div>
      </div>
    </div>
  </div>

  <div class="summary-card">
    This analysis identified <strong>${openVulns.length} open vulnerabilities</strong>
    across <strong>${graph.services.length} services</strong> with <strong>${graph.dependencies.length} dependency relationships</strong>.
    ${criticalCount > 0 ? `<strong style="color:var(--red)">${criticalCount} critical</strong> and <strong style="color:var(--orange)">${highCount} high</strong> severity vulnerabilities require immediate attention.` : 'No critical vulnerabilities were found.'}
    Full remediation reduces system risk from <strong style="color:var(--red)">${totalRiskBefore}%</strong> to
    <strong style="color:var(--green)">${totalRiskAfter}%</strong> — a <strong>${reduction}%</strong> reduction.
    ${urgentCompliance > 0 ? `<br><span style="color:var(--purple)"><strong>${urgentCompliance} compliance deadline${urgentCompliance !== 1 ? 's' : ''} within 14 days</strong> require prioritized action.</span>` : ''}
  </div>

${complianceSummary.violations.length > 0 ? `
  <!-- 2. Compliance Impact -->
  <div class="section-header">
    <span class="section-number">2</span>
    <span class="section-title">Compliance Impact</span>
  </div>

  <div class="table-wrap">
  <table>
    <thead><tr><th>Framework</th><th>Open Violations</th><th>Urgent (&lt;14d)</th><th>Affected CVEs</th></tr></thead>
    <tbody>
${complianceSummary.violations.map(v => `      <tr>
        <td><span class="badge badge-compliance">${v.framework}</span></td>
        <td>${v.vulnIds.length}</td>
        <td${v.urgentCount > 0 ? ' style="color:var(--red);font-weight:700"' : ''}>${v.urgentCount}</td>
        <td class="mono" style="font-size:11px;color:var(--text-dim)">${v.vulnIds.slice(0, 4).map(id => vulnMap.get(id)?.cveId ?? id).join(', ')}${v.vulnIds.length > 4 ? ` +${v.vulnIds.length - 4}` : ''}</td>
      </tr>`).join('\n')}
    </tbody>
  </table>
  </div>
` : ''}

  <!-- ${complianceSummary.violations.length > 0 ? '3' : '2'}. Ranked Patch Order -->
  <div class="section-header">
    <span class="section-number">${complianceSummary.violations.length > 0 ? '3' : '2'}</span>
    <span class="section-title">Ranked Patch Order</span>
  </div>

  <div class="summary-card" style="font-size:12px;color:var(--text-dim);margin-bottom:16px">
    Priority determined by Bayesian risk propagation, EPSS exploit scoring, compliance urgency,
    blast radius analysis, and Monte Carlo simulation (${simulation.iterations.toLocaleString()} iterations, ${Math.round(simulation.convergenceScore * 100)}% convergence).
  </div>

  <div class="table-wrap">
  <table>
    <thead><tr><th style="width:36px;text-align:center">#</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>Services</th><th>Cost</th><th>Compliance</th><th style="text-align:right">Confidence</th></tr></thead>
    <tbody>
${simulation.optimalOrder.map((vulnId, i) => {
  const vuln = vulnMap.get(vulnId)
  if (!vuln) return ''
  const ci = simulation.confidenceIntervals[i]
  const services = vuln.affectedServiceIds.map(sid => serviceMap.get(sid)?.name ?? sid).join(', ')
  const epssDiv = Math.abs(vuln.epssScore - vuln.cvssScore / 10)
  const epssColor = vuln.epssScore > 0.5 ? 'var(--red)' : vuln.epssScore > 0.2 ? 'var(--amber)' : 'var(--green)'
  const epssHigher = vuln.epssScore > vuln.cvssScore / 10
  const divergeLabel = epssDiv > 0.15 ? (epssHigher ? 'HIGH' : 'LOW') : ''
  const divergeClass = epssHigher ? 'epss-high' : 'epss-low'
  const blast = blastRadii[vulnId]
  const blastCount = blast ? blast.directServices.length + blast.cascadeServices.length : 0

  return `      <tr${i === 0 ? ' class="rank-1"' : ''}>
        <td class="rank-cell">${i + 1}</td>
        <td>
          <div class="cve-id">${vuln.cveId}</div>
          <div class="cve-title">${vuln.title}</div>
        </td>
        <td><span class="badge badge-${vuln.severity}">${vuln.severity}</span></td>
        <td class="mono">${vuln.cvssScore.toFixed(1)}</td>
        <td>
          <span class="epss-bar-track"><span class="epss-bar-fill" style="width:${Math.min(vuln.epssScore * 100, 100)}%;background:${epssColor}"></span></span>
          <span class="mono">${(vuln.epssScore * 100).toFixed(0)}%</span>
          ${divergeLabel ? `<span class="epss-diverge ${divergeClass}">${divergeLabel}</span>` : ''}
        </td>
        <td style="font-size:11px;color:var(--text-dim);max-width:120px">${services}${blastCount > 1 ? ` <span style="color:var(--amber);font-weight:700">(${blastCount} blast)</span>` : ''}</td>
        <td class="mono">${vuln.remediationCost}h / ${vuln.remediationDowntime}m</td>
        <td>${(vuln.complianceViolations ?? []).map(f => `<span class="badge badge-compliance" style="margin:1px 2px">${f}</span>`).join('') || '<span style="color:var(--text-faint)">—</span>'}</td>
        <td class="mono" style="text-align:right;color:${ci && ci.frequency > 0.7 ? 'var(--green)' : 'var(--text-dim)'}">${ci ? Math.round(ci.frequency * 100) + '%' : '—'}</td>
      </tr>`
}).join('\n')}
    </tbody>
  </table>
  </div>

  <!-- Service Risk Assessment -->
  <div class="section-header">
    <span class="section-number">${complianceSummary.violations.length > 0 ? '4' : '3'}</span>
    <span class="section-title">Service Risk Assessment</span>
  </div>

  <div class="service-grid">
${graph.services
  .sort((a, b) => (riskScores[b.id] ?? 0) - (riskScores[a.id] ?? 0))
  .map(s => {
    const risk = Math.round((riskScores[s.id] ?? 0) * 100)
    const rColor = risk > 70 ? 'var(--red)' : risk > 40 ? 'var(--amber)' : 'var(--green)'
    const vulnCount = graph.vulnerabilities.filter(v => v.affectedServiceIds.includes(s.id) && v.status === 'open').length
    return `    <div class="service-card">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <div>
          <div class="service-name">${s.name}</div>
          <div class="service-meta"><span class="badge badge-${s.tier}" style="font-size:8px;margin-right:4px">${s.tier}</span> SLA ${s.sla}% &middot; ${vulnCount} CVE${vulnCount !== 1 ? 's' : ''}</div>
        </div>
        <div class="service-risk" style="color:${rColor}">${risk}%</div>
      </div>
      <div class="risk-bar-track">
        <div class="risk-bar-fill" style="width:${risk}%;background:${rColor}"></div>
      </div>
      ${(s.complianceFrameworks ?? []).length > 0 ? `<div style="margin-top:8px">${s.complianceFrameworks.map(f => `<span class="badge badge-compliance" style="margin:1px 2px;font-size:8px">${f}</span>`).join('')}</div>` : ''}
    </div>`
  }).join('\n')}
  </div>

${schedule.length > 0 ? `
  <!-- Maintenance Schedule -->
  <div class="section-header">
    <span class="section-number">${complianceSummary.violations.length > 0 ? '5' : '4'}</span>
    <span class="section-title">Maintenance Schedule</span>
  </div>

  <div class="table-wrap">
  <table>
    <thead><tr><th>Week</th><th>Window</th><th>CVE</th><th>Severity</th><th>Service</th><th>Duration</th><th>Dependencies</th></tr></thead>
    <tbody>
${schedule.map(s => {
  const vuln = vulnMap.get(s.vulnId)
  const service = serviceMap.get(s.serviceId)
  return `      <tr>
        <td style="font-weight:700">Wk ${s.weekNumber}</td>
        <td style="font-size:11px">${s.windowDay} ${s.windowStart}-${s.windowEnd}</td>
        <td class="mono">${vuln?.cveId ?? s.vulnId}</td>
        <td>${vuln ? `<span class="badge badge-${vuln.severity}">${vuln.severity}</span>` : '—'}</td>
        <td style="font-size:12px">${service?.name ?? s.serviceId}</td>
        <td class="mono">${s.estimatedDuration}m</td>
        <td style="font-size:11px;color:var(--text-dim)">${s.dependsOn.length > 0 ? s.dependsOn.map(id => vulnMap.get(id)?.cveId ?? id).join(', ') : '—'}</td>
      </tr>`
}).join('\n')}
    </tbody>
  </table>
  </div>
` : ''}

  <!-- Methodology -->
  <div class="section-header">
    <span class="section-number">${complianceSummary.violations.length > 0 ? (schedule.length > 0 ? '6' : '5') : (schedule.length > 0 ? '5' : '4')}</span>
    <span class="section-title">Methodology</span>
  </div>

  <div class="method-grid">
    <div class="method-card">
      <div class="method-step">Step 1</div>
      <div class="method-title">Attack Graph Construction</div>
      <div class="method-desc">Models services as nodes and dependencies as directed edges. CVEs are attached to affected services. ${graph.services.length} services, ${graph.dependencies.length} edges, ${openVulns.length} CVEs.</div>
    </div>
    <div class="method-card">
      <div class="method-step">Step 2</div>
      <div class="method-title">Bayesian Risk Propagation</div>
      <div class="method-desc">Iterative belief propagation through dependency edges. EPSS scores weight real-world exploitability. Compliance frameworks add regulatory risk multipliers.</div>
    </div>
    <div class="method-card">
      <div class="method-step">Step 3</div>
      <div class="method-title">Monte Carlo Simulation</div>
      <div class="method-desc">${simulation.iterations.toLocaleString()} iterations with perturbed exploit probabilities. Greedy selection finds the patch ordering that maximally reduces total system risk. ${Math.round(simulation.convergenceScore * 100)}% convergence achieved.</div>
    </div>
    <div class="method-card">
      <div class="method-step">Step 4</div>
      <div class="method-title">Pareto Optimization</div>
      <div class="method-desc">Multi-objective optimization across risk reduction, cost (person-hours), and downtime. ${pareto.frontierIds.length} non-dominated solutions identified from ${pareto.solutions.length} candidates.</div>
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    <div>
      <div class="footer-left">FAVR &mdash; Flexible Attack Vector Risk</div>
      <div class="footer-disclaimer">This report is auto-generated. Validate findings with your security team before executing patches.</div>
    </div>
    <div class="footer-right">
      v${result.engineVersion} &middot; ${Math.round(simulation.convergenceScore * 100)}%
    </div>
  </div>

</div>
</body>
</html>`
}
