import { useState, useCallback } from 'react'
import { useAnalysisStore } from '../stores/analysisStore'
import type { FavrWhatIfResult } from '../../shared/types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
  low: 'text-blue-400'
}

export default function WhatIfView() {
  const result = useAnalysisStore(s => s.result)

  const [maxBudget, setMaxBudget] = useState<number>(50)
  const [maxDowntime, setMaxDowntime] = useState<number>(300)
  const [budgetEnabled, setBudgetEnabled] = useState(false)
  const [downtimeEnabled, setDowntimeEnabled] = useState(false)
  const [skipServiceIds, setSkipServiceIds] = useState<Set<string>>(new Set())
  const [whatIfResult, setWhatIfResult] = useState<FavrWhatIfResult | null>(null)
  const [loading, setLoading] = useState(false)

  const runWhatIf = useCallback(async () => {
    if (!result) return
    setLoading(true)
    try {
      const res = await window.api.invoke('analysis:whatIf', {
        maxBudgetHours: budgetEnabled ? maxBudget : null,
        skipServiceIds: Array.from(skipServiceIds),
        skipVulnIds: [],
        maxDowntimeMinutes: downtimeEnabled ? maxDowntime : null
      }) as FavrWhatIfResult
      setWhatIfResult(res)
    } catch (err) {
      console.error('What-if failed:', err)
    }
    setLoading(false)
  }, [result, maxBudget, maxDowntime, budgetEnabled, downtimeEnabled, skipServiceIds])

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center max-w-sm">
          <div className="w-14 h-14 rounded-2xl bg-surface-900 border border-surface-800 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-surface-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h2 className="text-lg font-bold text-white mb-1">No Scenario Data</h2>
          <p className="text-sm text-surface-500 leading-relaxed">Run an analysis from the Dashboard first, then explore tradeoffs with budget, downtime, and service constraints.</p>
          <p className="text-[10px] text-surface-600 mt-3 font-mono">Press 1 to go to Dashboard</p>
        </div>
      </div>
    )
  }

  const totalCostAll = result.graph.vulnerabilities
    .filter(v => v.status === 'open')
    .reduce((s, v) => s + v.remediationCost, 0)
  const totalDowntimeAll = result.graph.vulnerabilities
    .filter(v => v.status === 'open')
    .reduce((s, v) => s + v.remediationDowntime, 0)
  const vulnMap = new Map(result.graph.vulnerabilities.map(v => [v.id, v]))

  const toggleService = (id: string) => {
    setSkipServiceIds(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white mb-1">What-If Scenarios</h1>
          <p className="text-sm text-surface-500">
            Explore tradeoffs: constrain budget, downtime, or exclude services
          </p>
        </div>
        <button
          onClick={runWhatIf}
          disabled={loading}
          className="px-5 py-2.5 bg-white text-black text-sm font-bold rounded-btn hover:bg-surface-200 transition-all uppercase tracking-wide disabled:opacity-50 btn-hover"
        >
          {loading ? 'Computing...' : 'Run Scenario'}
        </button>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Left: Controls */}
        <div className="col-span-1 flex flex-col gap-4">
          {/* Budget constraint */}
          <div className="bg-surface-900 border border-surface-800 rounded-card p-4 animate-slideUp stagger-1">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-white">Budget Constraint</span>
              <button
                onClick={() => setBudgetEnabled(!budgetEnabled)}
                className={`w-9 h-5 rounded-full relative transition-colors ${budgetEnabled ? 'bg-white' : 'bg-surface-700'}`}
              >
                <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${budgetEnabled ? 'left-[18px] bg-black' : 'left-0.5 bg-surface-500'}`} />
              </button>
            </div>
            {budgetEnabled && (
              <>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] text-surface-500">Max person-hours</span>
                  <span className="text-sm font-bold text-white font-mono">{maxBudget}h</span>
                </div>
                <input
                  type="range"
                  min={1}
                  max={totalCostAll}
                  value={maxBudget}
                  onChange={(e) => setMaxBudget(Number(e.target.value))}
                  className="w-full accent-white"
                />
                <div className="flex justify-between text-[9px] text-surface-600 mt-1">
                  <span>1h</span>
                  <span>{totalCostAll}h (all)</span>
                </div>
              </>
            )}
          </div>

          {/* Downtime constraint */}
          <div className="bg-surface-900 border border-surface-800 rounded-card p-4 animate-slideUp stagger-2">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-white">Downtime Constraint</span>
              <button
                onClick={() => setDowntimeEnabled(!downtimeEnabled)}
                className={`w-9 h-5 rounded-full relative transition-colors ${downtimeEnabled ? 'bg-white' : 'bg-surface-700'}`}
              >
                <div className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${downtimeEnabled ? 'left-[18px] bg-black' : 'left-0.5 bg-surface-500'}`} />
              </button>
            </div>
            {downtimeEnabled && (
              <>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] text-surface-500">Max minutes</span>
                  <span className="text-sm font-bold text-white font-mono">{maxDowntime}m</span>
                </div>
                <input
                  type="range"
                  min={5}
                  max={totalDowntimeAll}
                  value={maxDowntime}
                  onChange={(e) => setMaxDowntime(Number(e.target.value))}
                  className="w-full accent-white"
                />
                <div className="flex justify-between text-[9px] text-surface-600 mt-1">
                  <span>5m</span>
                  <span>{totalDowntimeAll}m (all)</span>
                </div>
              </>
            )}
          </div>

          {/* Skip services */}
          <div className="bg-surface-900 border border-surface-800 rounded-card p-4 animate-slideUp stagger-3">
            <div className="text-xs font-bold text-white mb-3">Skip Services</div>
            <div className="flex flex-col gap-2">
              {result.graph.services.map(service => {
                const isSkipped = skipServiceIds.has(service.id)
                return (
                  <button
                    key={service.id}
                    onClick={() => toggleService(service.id)}
                    className={`flex items-center justify-between px-3 py-2 rounded-btn text-left transition-colors ${
                      isSkipped ? 'bg-red-500/10 border border-red-500/20' : 'bg-surface-800/50 border border-surface-800'
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${
                        isSkipped ? 'bg-red-400' :
                        service.tier === 'critical' ? 'bg-red-400' :
                        service.tier === 'high' ? 'bg-orange-400' :
                        service.tier === 'medium' ? 'bg-amber-400' : 'bg-blue-400'
                      }`} />
                      <span className={`text-xs ${isSkipped ? 'text-red-400 line-through' : 'text-white'}`}>
                        {service.name}
                      </span>
                    </div>
                    <span className="text-[10px] text-surface-600">{service.tier}</span>
                  </button>
                )
              })}
            </div>
          </div>
        </div>

        {/* Right: Results */}
        <div className="col-span-2">
          {!whatIfResult ? (
            <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card p-12 text-center h-full flex items-center justify-center">
              <div>
                <p className="text-sm text-surface-500 mb-2">Configure constraints and click "Run Scenario"</p>
                <p className="text-[10px] text-surface-600">See what happens if you only have {maxBudget}h of IT time this month</p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-4 animate-fadeIn">
              {/* Result stats */}
              <div className="grid grid-cols-4 gap-3">
                <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-1">
                  <div className={`text-2xl font-black ${whatIfResult.residualRisk > 0.5 ? 'text-red-400' : whatIfResult.residualRisk > 0.2 ? 'text-amber-400' : 'text-green-400'}`}>
                    {Math.round(whatIfResult.residualRisk * 100)}%
                  </div>
                  <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Residual Risk</div>
                </div>
                <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-2">
                  <div className="text-2xl font-black text-green-400">{whatIfResult.patchableVulns.length}</div>
                  <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Can Patch</div>
                </div>
                <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-3">
                  <div className="text-2xl font-black text-red-400">{whatIfResult.skippedVulns.length}</div>
                  <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Must Skip</div>
                </div>
                <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-4">
                  <div className="text-2xl font-black text-amber-400">{whatIfResult.totalCost}h</div>
                  <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Cost</div>
                </div>
              </div>

              {/* Comparison bar */}
              <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold text-white">Risk Comparison</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex-1">
                    <div className="text-[10px] text-surface-500 mb-1">Full Remediation</div>
                    <div className="w-full h-3 bg-surface-800 rounded-full overflow-hidden">
                      <div className="h-full bg-green-400 rounded-full" style={{ width: `${Math.round(result.simulation.totalRiskAfter * 100)}%` }} />
                    </div>
                    <div className="text-[10px] text-green-400 mt-0.5">{Math.round(result.simulation.totalRiskAfter * 100)}%</div>
                  </div>
                  <div className="flex-1">
                    <div className="text-[10px] text-surface-500 mb-1">This Scenario</div>
                    <div className="w-full h-3 bg-surface-800 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${whatIfResult.residualRisk > 0.5 ? 'bg-red-400' : 'bg-amber-400'}`} style={{ width: `${Math.round(whatIfResult.residualRisk * 100)}%` }} />
                    </div>
                    <div className={`text-[10px] mt-0.5 ${whatIfResult.residualRisk > 0.5 ? 'text-red-400' : 'text-amber-400'}`}>{Math.round(whatIfResult.residualRisk * 100)}%</div>
                  </div>
                  <div className="flex-1">
                    <div className="text-[10px] text-surface-500 mb-1">No Remediation</div>
                    <div className="w-full h-3 bg-surface-800 rounded-full overflow-hidden">
                      <div className="h-full bg-red-400 rounded-full" style={{ width: `${Math.round(result.simulation.totalRiskBefore * 100)}%` }} />
                    </div>
                    <div className="text-[10px] text-red-400 mt-0.5">{Math.round(result.simulation.totalRiskBefore * 100)}%</div>
                  </div>
                </div>
              </div>

              {/* Compliance gaps */}
              {whatIfResult.complianceGaps.length > 0 && (
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-card p-4">
                  <h3 className="text-xs font-bold text-purple-300 mb-3">Compliance Gaps (Unpatched)</h3>
                  <div className="grid gap-2">
                    {whatIfResult.complianceGaps.map(gap => (
                      <div key={gap.framework} className="flex items-center justify-between">
                        <span className="text-[10px] font-bold text-purple-400 bg-purple-500/15 px-2 py-0.5 rounded border border-purple-500/20">
                          {gap.framework}
                        </span>
                        <span className="text-[10px] text-purple-400/70">
                          {gap.vulnIds.length} unpatched violation{gap.vulnIds.length !== 1 ? 's' : ''}: {gap.vulnIds.slice(0, 3).map(id => vulnMap.get(id)?.cveId ?? id).join(', ')}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Skipped vulns */}
              {whatIfResult.skippedVulns.length > 0 && (
                <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
                  <h3 className="text-xs font-bold text-white mb-3">Skipped Vulnerabilities ({whatIfResult.skippedVulns.length})</h3>
                  <div className="grid gap-1.5">
                    {whatIfResult.skippedVulns.map(vulnId => {
                      const vuln = vulnMap.get(vulnId)
                      if (!vuln) return null
                      return (
                        <div key={vulnId} className="flex items-center gap-2 bg-surface-800/30 rounded-btn px-3 py-2">
                          <span className={`text-[10px] font-bold ${SEVERITY_COLORS[vuln.severity]}`}>{vuln.severity}</span>
                          <span className="text-xs text-surface-400">{vuln.cveId}</span>
                          <span className="text-[10px] text-surface-600 flex-1 truncate">{vuln.title}</span>
                          <span className="text-[10px] text-surface-600 font-mono">{vuln.remediationCost}h / {vuln.remediationDowntime}m</span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Per-service residual risk */}
              <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
                <h3 className="text-xs font-bold text-white mb-3">Residual Risk by Service</h3>
                <div className="grid gap-2">
                  {result.graph.services
                    .sort((a, b) => (whatIfResult.residualRiskByService[b.id] ?? 0) - (whatIfResult.residualRiskByService[a.id] ?? 0))
                    .map(service => {
                      const risk = Math.round((whatIfResult.residualRiskByService[service.id] ?? 0) * 100)
                      const origRisk = Math.round((result.riskScores[service.id] ?? 0) * 100)
                      const isSkipped = skipServiceIds.has(service.id)
                      return (
                        <div key={service.id} className="flex items-center gap-3 bg-surface-800/30 rounded-btn px-3 py-2">
                          <span className="text-xs font-bold text-white w-32 truncate">{service.name}</span>
                          <div className="flex-1 h-2 bg-surface-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${
                                risk >= 70 ? 'bg-red-400' : risk >= 40 ? 'bg-amber-400' : 'bg-green-400'
                              }`}
                              style={{ width: `${risk}%` }}
                            />
                          </div>
                          <span className="text-xs font-mono text-surface-300 w-12 text-right">{risk}%</span>
                          {isSkipped && <span className="text-[9px] text-red-400 font-bold">SKIP</span>}
                          {!isSkipped && risk < origRisk && (
                            <span className="text-[9px] text-green-400 font-mono">-{origRisk - risk}%</span>
                          )}
                        </div>
                      )
                    })}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
