import { useState } from 'react'
import { useAnalysisStore } from '../stores/analysisStore'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30'
}

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-400',
  high: 'bg-orange-400',
  medium: 'bg-amber-400',
  low: 'bg-blue-400'
}

export default function FlowsView() {
  const result = useAnalysisStore(s => s.result)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [filter, setFilter] = useState<string>('all')

  if (!result) {
    return (
      <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-white mb-1">Vulnerabilities</h1>
          <p className="text-sm text-surface-500">Run an analysis to see prioritized vulnerabilities</p>
        </div>
        <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card p-12 text-center">
          <p className="text-sm text-surface-500">No analysis results yet. Go to Dashboard to run an analysis.</p>
        </div>
      </div>
    )
  }

  const vulns = result.graph.vulnerabilities
  const optimalOrder = result.simulation.optimalOrder
  const confidenceIntervals = result.simulation.confidenceIntervals

  // Get patch position for each vuln
  const positionMap = new Map<string, number>()
  optimalOrder.forEach((id, i) => positionMap.set(id, i + 1))

  // Filter
  const filtered = filter === 'all'
    ? vulns
    : vulns.filter(v => v.severity === filter)

  // Sort by optimal patch order
  const sorted = [...filtered].sort((a, b) => {
    const posA = positionMap.get(a.id) ?? 999
    const posB = positionMap.get(b.id) ?? 999
    return posA - posB
  })

  const counts = {
    all: vulns.length,
    critical: vulns.filter(v => v.severity === 'critical').length,
    high: vulns.filter(v => v.severity === 'high').length,
    medium: vulns.filter(v => v.severity === 'medium').length,
    low: vulns.filter(v => v.severity === 'low').length,
  }

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white mb-1">Vulnerabilities</h1>
          <p className="text-sm text-surface-500">
            {vulns.length} CVEs prioritized by FAVR engine &middot; Optimal patch order shown
          </p>
        </div>
      </div>

      {/* Filter tabs */}
      <div className="flex gap-2 mb-4">
        {(['all', 'critical', 'high', 'medium', 'low'] as const).map(sev => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-btn border transition-all duration-150 btn-hover ${
              filter === sev
                ? sev === 'all'
                  ? 'bg-surface-800 border-white/20 text-white'
                  : SEVERITY_COLORS[sev]
                : 'bg-surface-900 border-surface-800 text-surface-500 hover:border-surface-700'
            }`}
          >
            {sev} ({counts[sev]})
          </button>
        ))}
      </div>

      {/* Vulnerability list */}
      <div className="flex flex-col gap-3">
        {sorted.map((vuln, idx) => {
          const position = positionMap.get(vuln.id) ?? null
          const ci = position ? confidenceIntervals[position - 1] : null
          const isExpanded = expandedId === vuln.id
          const sevStyle = SEVERITY_COLORS[vuln.severity]
          const services = result.graph.services.filter(s =>
            vuln.affectedServiceIds.includes(s.id)
          )

          return (
            <div
              key={vuln.id}
              className="bg-surface-900 border border-surface-800 rounded-card overflow-hidden card-hover animate-slideUp"
              style={{ animationDelay: `${Math.min(idx * 50, 400)}ms` }}
            >
              {/* Header row */}
              <button
                onClick={() => setExpandedId(isExpanded ? null : vuln.id)}
                className="w-full px-5 py-4 flex items-center gap-4 text-left hover:bg-surface-800/30 transition-colors"
              >
                {/* Patch order badge */}
                {position && (
                  <div className="w-8 h-8 rounded-full bg-surface-800 flex items-center justify-center text-xs font-black text-white shrink-0">
                    #{position}
                  </div>
                )}

                {/* Severity badge */}
                <div className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border shrink-0 ${sevStyle}`}>
                  {vuln.severity}
                </div>

                {/* CVE info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-sm font-bold text-white">{vuln.cveId}</span>
                    <span className="text-[10px] text-surface-500 font-mono">CVSS {vuln.cvssScore.toFixed(1)}</span>
                  </div>
                  <span className="text-xs text-surface-400 truncate block">{vuln.title}</span>
                </div>

                {/* Confidence */}
                {ci && (
                  <div className="text-right shrink-0">
                    <div className="text-xs font-bold text-surface-300">{Math.round(ci.frequency * 100)}%</div>
                    <div className="text-[10px] text-surface-600">confidence</div>
                  </div>
                )}

                {/* Services count */}
                <div className="text-right shrink-0">
                  <div className="text-xs font-bold text-surface-300">{services.length}</div>
                  <div className="text-[10px] text-surface-600">service{services.length !== 1 ? 's' : ''}</div>
                </div>

                {/* Expand arrow */}
                <span className={`text-surface-500 transition-transform shrink-0 ${isExpanded ? 'rotate-180' : ''}`}>
                  &#9662;
                </span>
              </button>

              {/* Expanded details */}
              {isExpanded && (
                <div className="border-t border-surface-800/50 px-5 py-4 animate-fadeIn">
                  <div className="grid grid-cols-2 gap-6">
                    {/* Left: Details */}
                    <div>
                      <div className="text-[10px] font-bold text-surface-500 uppercase tracking-wider mb-2">Details</div>
                      <div className="grid grid-cols-3 gap-3 mb-4">
                        <div>
                          <div className="text-[10px] text-surface-600">CVSS Score</div>
                          <div className="text-sm font-bold text-white">{vuln.cvssScore.toFixed(1)}</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-surface-600">EPSS Score</div>
                          <div className={`text-sm font-bold ${vuln.epssScore > 0.5 ? 'text-red-400' : vuln.epssScore > 0.2 ? 'text-amber-400' : 'text-green-400'}`}>
                            {(vuln.epssScore * 100).toFixed(1)}%
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-surface-600">Exploit Probability</div>
                          <div className="text-sm font-bold text-white">{Math.round(vuln.exploitProbability * 100)}%</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-surface-600">Patch Cost</div>
                          <div className="text-sm font-bold text-white">{vuln.remediationCost}h</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-surface-600">Downtime</div>
                          <div className="text-sm font-bold text-white">{vuln.remediationDowntime}min</div>
                        </div>
                        {vuln.complianceDeadlineDays != null && (
                          <div>
                            <div className="text-[10px] text-surface-600">Compliance Deadline</div>
                            <div className={`text-sm font-bold ${vuln.complianceDeadlineDays <= 14 ? 'text-red-400' : vuln.complianceDeadlineDays <= 30 ? 'text-amber-400' : 'text-surface-300'}`}>
                              {vuln.complianceDeadlineDays}d
                            </div>
                          </div>
                        )}
                      </div>

                      {/* EPSS vs CVSS Divergence */}
                      {Math.abs(vuln.epssScore - vuln.cvssScore / 10) > 0.15 && (
                        <div className={`mb-4 p-2 rounded-btn border text-[10px] ${
                          vuln.epssScore > vuln.cvssScore / 10
                            ? 'bg-red-500/10 border-red-500/20 text-red-400'
                            : 'bg-green-500/10 border-green-500/20 text-green-400'
                        }`}>
                          {vuln.epssScore > vuln.cvssScore / 10
                            ? `EPSS (${(vuln.epssScore * 100).toFixed(0)}%) significantly HIGHER than CVSS-implied risk — real-world exploit activity is high.`
                            : `EPSS (${(vuln.epssScore * 100).toFixed(0)}%) significantly LOWER than CVSS (${vuln.cvssScore.toFixed(1)}) implies — low real-world exploitation.`
                          }
                        </div>
                      )}

                      {/* Compliance Violations */}
                      {vuln.complianceViolations && vuln.complianceViolations.length > 0 && (
                        <div className="mb-4">
                          <div className="text-[10px] text-surface-600 mb-1">Compliance Violations</div>
                          <div className="flex flex-wrap gap-1">
                            {vuln.complianceViolations.map((f: string) => (
                              <span key={f} className="text-[9px] font-bold px-2 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/20">
                                {f}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Blast Radius */}
                      {result.blastRadii?.[vuln.id] && result.blastRadii[vuln.id].cascadeServices.length > 0 && (
                        <div className="mb-4 bg-amber-500/10 border border-amber-500/20 rounded-btn p-2">
                          <div className="text-[10px] font-bold text-amber-400 mb-1">
                            Blast Radius: {result.blastRadii[vuln.id].totalDowntimeMinutes}min total downtime
                          </div>
                          <div className="text-[10px] text-amber-400/70">
                            Cascade: {result.blastRadii[vuln.id].cascadeServices.map((sid: string) => {
                              const s = result.graph.services.find(sv => sv.id === sid)
                              return s?.name ?? sid
                            }).join(', ')}
                          </div>
                        </div>
                      )}

                      {/* Description */}
                      {vuln.description && (
                        <div className="mb-4">
                          <div className="text-[10px] text-surface-600 mb-1">Description</div>
                          <p className="text-xs text-surface-400 leading-relaxed">{vuln.description}</p>
                        </div>
                      )}

                      {/* Affected package */}
                      {vuln.affectedPackage && (
                        <div>
                          <div className="text-[10px] text-surface-600 mb-1">Affected Package</div>
                          <div className="text-xs text-surface-300 font-mono bg-surface-800 px-2 py-1 rounded inline-block">
                            {vuln.affectedPackage}
                            {vuln.patchedVersion && ` → ${vuln.patchedVersion}`}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Right: Affected Services & Alternatives */}
                    <div>
                      <div className="text-[10px] font-bold text-surface-500 uppercase tracking-wider mb-2">Affected Services</div>
                      <div className="flex flex-col gap-2 mb-4">
                        {services.map(s => {
                          const risk = result.riskScores[s.id] ?? 0
                          return (
                            <div key={s.id} className="flex items-center gap-2 bg-surface-800/50 rounded-btn px-3 py-2">
                              <div className={`w-2 h-2 rounded-full ${SEVERITY_DOT[s.tier]}`} />
                              <span className="text-xs text-white flex-1">{s.name}</span>
                              <span className="text-[10px] text-surface-500 font-mono">{Math.round(risk * 100)}% risk</span>
                            </div>
                          )
                        })}
                      </div>

                      {/* Alternative positions */}
                      {ci && ci.alternatives.length > 0 && (
                        <div>
                          <div className="text-[10px] font-bold text-surface-500 uppercase tracking-wider mb-2">
                            Monte Carlo Alternatives
                          </div>
                          <div className="flex flex-col gap-1">
                            {ci.alternatives.map((alt, i) => (
                              <div key={i} className="flex items-center gap-2 text-[10px]">
                                <span className="text-surface-600 w-20 truncate">{alt.cveId}</span>
                                <div className="flex-1 h-1 bg-surface-800 rounded-full overflow-hidden">
                                  <div className="h-full bg-surface-600 rounded-full" style={{ width: `${alt.frequency * 100}%` }} />
                                </div>
                                <span className="text-surface-500 font-mono w-10 text-right">{Math.round(alt.frequency * 100)}%</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
