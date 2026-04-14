import { useState, useEffect, useRef, useCallback } from 'react'
import { useAnalysisStore } from '../../stores/analysisStore'
import type { FavrWhatIfResult } from '../../../shared/types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30'
}

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-400',
  high: 'bg-orange-400',
  medium: 'bg-amber-400',
  low: 'bg-blue-400'
}

function useCountUp(target: number, duration = 600): number {
  const [value, setValue] = useState(0)
  const startRef = useRef<number | null>(null)
  const prevTarget = useRef(0)

  useEffect(() => {
    const from = prevTarget.current
    prevTarget.current = target
    startRef.current = null

    let raf: number
    function tick(ts: number) {
      if (startRef.current === null) startRef.current = ts
      const progress = Math.min((ts - startRef.current) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(Math.round(from + (target - from) * eased))
      if (progress < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])

  return value
}

function MiniGauge({ value, size = 80, label }: { value: number; size?: number; label: string }) {
  const strokeWidth = 6
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const progress = Math.min(value, 100) / 100
  const dashOffset = circumference * (1 - progress)
  const color = value > 70 ? '#EF4444' : value > 40 ? '#F59E0B' : '#22C55E'

  return (
    <div className="flex flex-col items-center">
      <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#27272A" strokeWidth={strokeWidth} />
          <circle
            cx={size / 2} cy={size / 2} r={radius} fill="none"
            stroke={color} strokeWidth={strokeWidth} strokeLinecap="round"
            strokeDasharray={circumference} strokeDashoffset={dashOffset}
            style={{ transition: 'stroke-dashoffset 0.8s ease-out' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-lg font-black text-white">{value}%</span>
        </div>
      </div>
      <span className="text-[10px] text-surface-500 uppercase font-bold mt-1.5 tracking-wider">{label}</span>
    </div>
  )
}

function Toggle({ enabled, onChange, label, icon }: { enabled: boolean; onChange: () => void; label: string; icon: JSX.Element }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <span className={`transition-colors ${enabled ? 'text-white' : 'text-surface-600'}`}>{icon}</span>
        <span className={`text-xs font-bold transition-colors ${enabled ? 'text-white' : 'text-surface-400'}`}>{label}</span>
      </div>
      <button
        onClick={onChange}
        className={`w-10 h-[22px] rounded-full relative transition-all duration-200 ${enabled ? 'bg-white' : 'bg-surface-700 hover:bg-surface-600'}`}
      >
        <div className={`absolute top-[3px] w-4 h-4 rounded-full transition-all duration-200 ${enabled ? 'left-[21px] bg-black' : 'left-[3px] bg-surface-400'}`} />
      </button>
    </div>
  )
}

export default function WhatIfTab() {
  const result = useAnalysisStore(s => s.result)

  const [maxBudget, setMaxBudget] = useState<number>(50)
  const [maxDowntime, setMaxDowntime] = useState<number>(300)
  const [budgetEnabled, setBudgetEnabled] = useState(false)
  const [downtimeEnabled, setDowntimeEnabled] = useState(false)
  const [skipServiceIds, setSkipServiceIds] = useState<Set<string>>(new Set())
  const [whatIfResult, setWhatIfResult] = useState<FavrWhatIfResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [scenarioCount, setScenarioCount] = useState(0)

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
      setScenarioCount(c => c + 1)
    } catch (err) {
      console.error('What-if failed:', err)
    }
    setLoading(false)
  }, [result, maxBudget, maxDowntime, budgetEnabled, downtimeEnabled, skipServiceIds])

  const handleReset = () => {
    setBudgetEnabled(false)
    setDowntimeEnabled(false)
    setSkipServiceIds(new Set())
    setWhatIfResult(null)
    setMaxBudget(50)
    setMaxDowntime(300)
  }

  if (!result) return null

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

  const activeConstraints = [
    budgetEnabled && `${maxBudget}h budget`,
    downtimeEnabled && `${maxDowntime}m downtime`,
    skipServiceIds.size > 0 && `${skipServiceIds.size} skipped`
  ].filter(Boolean)

  const fullRemRisk = Math.round(result.simulation.totalRiskAfter * 100)
  const noRemRisk = Math.round(result.simulation.totalRiskBefore * 100)
  const scenarioRisk = whatIfResult ? Math.round(whatIfResult.residualRisk * 100) : null

  return (
    <>
      {/* Controls header */}
      <div className="flex items-center justify-between mb-4">
        <p className="text-sm text-surface-500">
          Explore tradeoffs: constrain budget, downtime, or exclude services
        </p>
        <div className="flex items-center gap-2">
          {whatIfResult && (
            <button
              onClick={handleReset}
              className="px-4 py-2.5 bg-surface-800 border border-surface-700 text-surface-300 text-xs font-bold rounded-btn hover:bg-surface-700 hover:text-white transition-all btn-hover"
            >
              Reset
            </button>
          )}
          <button
            onClick={runWhatIf}
            disabled={loading}
            className="px-5 py-2.5 bg-white text-black text-sm font-bold rounded-btn hover:bg-surface-200 transition-all disabled:opacity-50 btn-hover flex items-center gap-2"
          >
            {loading ? (
              <>
                <div className="w-3.5 h-3.5 rounded-full border-2 border-black border-t-transparent animate-spin" />
                Computing...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Run Scenario
              </>
            )}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-12 gap-5">
        {/* Left: Controls */}
        <div className="col-span-4 flex flex-col gap-4">
          {activeConstraints.length > 0 && (
            <div className="bg-surface-800/50 border border-surface-800 rounded-card px-4 py-3 flex items-center gap-2 animate-fadeIn">
              <svg className="w-3.5 h-3.5 text-amber-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
              </svg>
              <span className="text-[10px] text-surface-400 font-mono">{activeConstraints.join(' · ')}</span>
            </div>
          )}

          {/* Budget constraint */}
          <div className={`bg-surface-900 border rounded-card p-4 transition-all duration-200 ${budgetEnabled ? 'border-amber-500/30' : 'border-surface-800'}`}>
            <Toggle
              enabled={budgetEnabled}
              onChange={() => setBudgetEnabled(!budgetEnabled)}
              label="Budget Constraint"
              icon={
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
            />
            <div className={`overflow-hidden transition-all duration-300 ${budgetEnabled ? 'max-h-40 mt-4 opacity-100' : 'max-h-0 mt-0 opacity-0'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] text-surface-500">Max person-hours</span>
                <span className="text-sm font-black text-amber-400 font-mono">{maxBudget}h</span>
              </div>
              <input
                type="range"
                min={1}
                max={totalCostAll}
                value={maxBudget}
                onChange={(e) => setMaxBudget(Number(e.target.value))}
                className="w-full accent-amber-400"
              />
              <div className="flex justify-between text-[9px] text-surface-600 mt-1">
                <span>1h</span>
                <span className="text-surface-500">{Math.round(maxBudget / totalCostAll * 100)}% of total</span>
                <span>{totalCostAll}h</span>
              </div>
            </div>
          </div>

          {/* Downtime constraint */}
          <div className={`bg-surface-900 border rounded-card p-4 transition-all duration-200 ${downtimeEnabled ? 'border-blue-500/30' : 'border-surface-800'}`}>
            <Toggle
              enabled={downtimeEnabled}
              onChange={() => setDowntimeEnabled(!downtimeEnabled)}
              label="Downtime Limit"
              icon={
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              }
            />
            <div className={`overflow-hidden transition-all duration-300 ${downtimeEnabled ? 'max-h-40 mt-4 opacity-100' : 'max-h-0 mt-0 opacity-0'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] text-surface-500">Max minutes</span>
                <span className="text-sm font-black text-blue-400 font-mono">{maxDowntime}m</span>
              </div>
              <input
                type="range"
                min={5}
                max={totalDowntimeAll}
                value={maxDowntime}
                onChange={(e) => setMaxDowntime(Number(e.target.value))}
                className="w-full accent-blue-400"
              />
              <div className="flex justify-between text-[9px] text-surface-600 mt-1">
                <span>5m</span>
                <span className="text-surface-500">{Math.round(maxDowntime / totalDowntimeAll * 100)}% of total</span>
                <span>{totalDowntimeAll}m</span>
              </div>
            </div>
          </div>

          {/* Skip services */}
          <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
            <div className="flex items-center gap-2 mb-3">
              <svg className="w-4 h-4 text-surface-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
              </svg>
              <span className="text-xs font-bold text-white">Exclude Services</span>
              {skipServiceIds.size > 0 && (
                <span className="text-[9px] bg-red-500/15 text-red-400 px-1.5 py-0.5 rounded font-bold">{skipServiceIds.size}</span>
              )}
            </div>
            <div className="flex flex-col gap-1.5">
              {result.graph.services.map(service => {
                const isSkipped = skipServiceIds.has(service.id)
                const risk = Math.round((result.riskScores[service.id] ?? 0) * 100)
                return (
                  <button
                    key={service.id}
                    onClick={() => toggleService(service.id)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-btn text-left transition-all duration-150 group ${
                      isSkipped
                        ? 'bg-red-500/10 border border-red-500/20 hover:bg-red-500/15'
                        : 'bg-surface-800/40 border border-surface-800 hover:bg-surface-800/70 hover:border-surface-700'
                    }`}
                  >
                    <div className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-all ${
                      isSkipped ? 'bg-red-500/20 border-red-500/50' : 'border-surface-600 group-hover:border-surface-500'
                    }`}>
                      {isSkipped && (
                        <svg className="w-3 h-3 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      )}
                    </div>
                    <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${isSkipped ? 'bg-red-400/50' : SEV_DOT[service.tier] ?? 'bg-surface-500'}`} />
                    <span className={`text-xs flex-1 truncate transition-colors ${isSkipped ? 'text-red-400/70 line-through' : 'text-white'}`}>
                      {service.name}
                    </span>
                    <span className="text-[9px] text-surface-600 font-mono">{risk}%</span>
                  </button>
                )
              })}
            </div>
          </div>
        </div>

        {/* Right: Results */}
        <div className="col-span-8">
          {!whatIfResult ? (
            <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card h-full flex items-center justify-center min-h-[300px]">
              <div className="text-center max-w-xs">
                <div className="w-12 h-12 rounded-xl bg-surface-800 flex items-center justify-center mx-auto mb-4">
                  <svg className="w-6 h-6 text-surface-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <p className="text-sm text-surface-400 font-semibold mb-1">Configure & Run</p>
                <p className="text-[11px] text-surface-600 leading-relaxed">
                  Set budget or downtime constraints, exclude services, then click "Run Scenario" to see the impact on your risk posture.
                </p>
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-4" key={scenarioCount}>
              {/* Scenario summary banner */}
              <div className="bg-surface-900 border border-surface-800 rounded-card p-4 animate-slideUp stagger-1">
                <div className="flex items-center gap-3 mb-4">
                  <svg className="w-4 h-4 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <span className="text-xs font-bold text-white">Scenario Result</span>
                  {activeConstraints.length > 0 && (
                    <span className="text-[9px] text-surface-500 font-mono">{activeConstraints.join(' · ')}</span>
                  )}
                </div>

                <div className="flex items-center justify-around">
                  <MiniGauge value={fullRemRisk} label="Full Fix" />
                  <div className="flex flex-col items-center gap-1">
                    <svg className="w-5 h-5 text-surface-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                  </div>
                  <MiniGauge value={scenarioRisk!} label="This Scenario" />
                  <div className="flex flex-col items-center gap-1">
                    <svg className="w-5 h-5 text-surface-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                  </div>
                  <MiniGauge value={noRemRisk} label="No Fix" />
                </div>

                <div className="mt-4 pt-3 border-t border-surface-800 flex items-center justify-center gap-6">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-surface-500">vs Full Fix:</span>
                    <span className={`text-xs font-bold font-mono ${scenarioRisk! > fullRemRisk ? 'text-red-400' : 'text-green-400'}`}>
                      {scenarioRisk! > fullRemRisk ? '+' : ''}{scenarioRisk! - fullRemRisk}%
                    </span>
                  </div>
                  <div className="w-px h-3 bg-surface-800" />
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-surface-500">vs No Fix:</span>
                    <span className="text-xs font-bold text-green-400 font-mono">
                      -{noRemRisk - scenarioRisk!}%
                    </span>
                  </div>
                  <div className="w-px h-3 bg-surface-800" />
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-surface-500">Coverage:</span>
                    <span className="text-xs font-bold text-white font-mono">
                      {whatIfResult.patchableVulns.length}/{whatIfResult.patchableVulns.length + whatIfResult.skippedVulns.length} CVEs
                    </span>
                  </div>
                </div>
              </div>

              {/* Stat cards */}
              <div className="grid grid-cols-4 gap-3 animate-slideUp stagger-2">
                <StatCard
                  value={scenarioRisk!}
                  suffix="%"
                  label="Residual Risk"
                  color={scenarioRisk! > 50 ? 'text-red-400' : scenarioRisk! > 20 ? 'text-amber-400' : 'text-green-400'}
                  icon={
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                  }
                />
                <StatCard
                  value={whatIfResult.patchableVulns.length}
                  label="Can Patch"
                  color="text-green-400"
                  icon={
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  }
                />
                <StatCard
                  value={whatIfResult.skippedVulns.length}
                  label="Must Skip"
                  color="text-red-400"
                  icon={
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  }
                />
                <StatCard
                  value={whatIfResult.totalCost}
                  suffix="h"
                  label="Total Cost"
                  color="text-amber-400"
                  icon={
                    <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  }
                />
              </div>

              {/* Compliance gaps */}
              {whatIfResult.complianceGaps.length > 0 && (
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-card p-4 animate-slideUp stagger-3">
                  <div className="flex items-center gap-2 mb-3">
                    <svg className="w-4 h-4 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                    <h3 className="text-xs font-bold text-purple-300">Compliance Gaps</h3>
                    <span className="text-[9px] bg-purple-500/20 text-purple-400 px-1.5 py-0.5 rounded font-bold">{whatIfResult.complianceGaps.length}</span>
                  </div>
                  <div className="grid gap-2">
                    {whatIfResult.complianceGaps.map(gap => (
                      <div key={gap.framework} className="flex items-center gap-3 bg-purple-500/5 rounded-btn px-3 py-2">
                        <span className="text-[10px] font-bold text-purple-400 bg-purple-500/15 px-2 py-0.5 rounded border border-purple-500/20 shrink-0">
                          {gap.framework}
                        </span>
                        <span className="text-[10px] text-purple-400/70 truncate">
                          {gap.vulnIds.length} unpatched: {gap.vulnIds.slice(0, 3).map(id => vulnMap.get(id)?.cveId ?? id).join(', ')}
                          {gap.vulnIds.length > 3 && ` +${gap.vulnIds.length - 3} more`}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Patchable vs Skipped */}
              <div className="grid grid-cols-2 gap-4 animate-slideUp stagger-4">
                <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-2 h-2 rounded-full bg-green-400" />
                    <h3 className="text-xs font-bold text-white">Patchable ({whatIfResult.patchableVulns.length})</h3>
                  </div>
                  <div className="flex flex-col gap-1.5 max-h-48 overflow-y-auto">
                    {whatIfResult.patchableVulns.map((vulnId, i) => {
                      const vuln = vulnMap.get(vulnId)
                      if (!vuln) return null
                      return (
                        <div key={vulnId} className="flex items-center gap-2 bg-surface-800/30 rounded-btn px-3 py-1.5">
                          <span className="text-[9px] font-mono text-surface-600 w-4 text-right">{i + 1}</span>
                          <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEV_DOT[vuln.severity]}`} />
                          <span className="text-[11px] text-white flex-1 truncate">{vuln.cveId}</span>
                          <span className="text-[9px] text-surface-600 font-mono">{vuln.remediationCost}h</span>
                        </div>
                      )
                    })}
                  </div>
                </div>

                <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <div className="w-2 h-2 rounded-full bg-red-400" />
                    <h3 className="text-xs font-bold text-white">Skipped ({whatIfResult.skippedVulns.length})</h3>
                  </div>
                  {whatIfResult.skippedVulns.length === 0 ? (
                    <div className="text-center py-6">
                      <span className="text-[10px] text-surface-600">All vulnerabilities can be patched</span>
                    </div>
                  ) : (
                    <div className="flex flex-col gap-1.5 max-h-48 overflow-y-auto">
                      {whatIfResult.skippedVulns.map(vulnId => {
                        const vuln = vulnMap.get(vulnId)
                        if (!vuln) return null
                        return (
                          <div key={vulnId} className="flex items-center gap-2 bg-red-500/5 border border-red-500/10 rounded-btn px-3 py-1.5">
                            <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEV_DOT[vuln.severity]}`} />
                            <span className="text-[11px] text-surface-400 flex-1 truncate">{vuln.cveId}</span>
                            <span className={`text-[9px] font-bold uppercase px-1 py-0.5 rounded ${SEVERITY_COLORS[vuln.severity]}`}>{vuln.severity}</span>
                            <span className="text-[9px] text-surface-600 font-mono">{vuln.remediationCost}h</span>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* Per-service residual risk */}
              <div className="bg-surface-900 border border-surface-800 rounded-card p-4 animate-slideUp stagger-5">
                <div className="flex items-center gap-2 mb-3">
                  <svg className="w-4 h-4 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                  </svg>
                  <h3 className="text-xs font-bold text-white">Residual Risk by Service</h3>
                </div>
                <div className="grid gap-2">
                  {[...result.graph.services]
                    .sort((a, b) => (whatIfResult.residualRiskByService[b.id] ?? 0) - (whatIfResult.residualRiskByService[a.id] ?? 0))
                    .map(service => {
                      const risk = Math.round((whatIfResult.residualRiskByService[service.id] ?? 0) * 100)
                      const origRisk = Math.round((result.riskScores[service.id] ?? 0) * 100)
                      const isSkipped = skipServiceIds.has(service.id)
                      const reduced = origRisk - risk
                      return (
                        <div key={service.id} className={`flex items-center gap-3 rounded-btn px-3 py-2.5 transition-all ${
                          isSkipped ? 'bg-red-500/5 border border-red-500/10' : 'bg-surface-800/30'
                        }`}>
                          <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEV_DOT[service.tier] ?? 'bg-surface-500'}`} />
                          <span className={`text-xs font-bold w-36 truncate ${isSkipped ? 'text-red-400/70' : 'text-white'}`}>{service.name}</span>
                          <div className="flex-1 h-2 bg-surface-800 rounded-full overflow-hidden relative">
                            <div className="absolute h-full rounded-full bg-surface-700 opacity-40" style={{ width: `${origRisk}%` }} />
                            <div
                              className={`relative h-full rounded-full transition-all duration-500 ${
                                risk >= 70 ? 'bg-red-400' : risk >= 40 ? 'bg-amber-400' : 'bg-green-400'
                              }`}
                              style={{ width: `${risk}%` }}
                            />
                          </div>
                          <span className="text-xs font-mono text-surface-300 w-10 text-right">{risk}%</span>
                          {isSkipped && <span className="text-[9px] text-red-400 font-bold bg-red-500/10 px-1.5 py-0.5 rounded">SKIP</span>}
                          {!isSkipped && reduced > 0 && (
                            <span className="text-[9px] text-green-400 font-mono font-bold">-{reduced}%</span>
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
    </>
  )
}

function StatCard({ value, suffix, label, color, icon }: { value: number; suffix?: string; label: string; color: string; icon: JSX.Element }) {
  const animated = useCountUp(value, 500)
  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4 card-hover">
      <div className={`flex items-center gap-1.5 mb-2 ${color}`}>
        {icon}
        <span className="text-[9px] text-surface-500 uppercase font-bold tracking-wider">{label}</span>
      </div>
      <div className={`text-2xl font-black ${color}`}>{animated}{suffix ?? ''}</div>
    </div>
  )
}
