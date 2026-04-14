import { useState } from 'react'
import { useAnalysisStore } from '../stores/analysisStore'
import RiskReductionCurve from './charts/RiskReductionCurve'
import ParetoFrontier from './charts/ParetoFrontier'
import ScheduleTab from './tabs/ScheduleTab'
import WhatIfTab from './tabs/WhatIfTab'

type Tab = 'overview' | 'schedule' | 'whatif'

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'schedule', label: 'Schedule' },
  { id: 'whatif', label: 'What-If' },
]

export default function BudgetView() {
  const result = useAnalysisStore(s => s.result)
  const [activeTab, setActiveTab] = useState<Tab>('overview')

  if (!result) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center max-w-sm">
          <div className="w-14 h-14 rounded-2xl bg-surface-900 border border-surface-800 flex items-center justify-center mx-auto mb-4">
            <svg className="w-7 h-7 text-surface-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <h2 className="text-lg font-bold text-white mb-1">No Risk Analysis Yet</h2>
          <p className="text-sm text-surface-500 leading-relaxed">Run an analysis from the Dashboard to see Bayesian risk propagation, Monte Carlo simulation, and Pareto optimization results.</p>
          <p className="text-[10px] text-surface-600 mt-3 font-mono">Press 1 to go to Dashboard</p>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-hidden">
      {/* Header + Tabs */}
      <div className="mb-4 shrink-0">
        <h1 className="text-xl font-bold text-white mb-1">Risk Analysis</h1>
        <p className="text-sm text-surface-500 mb-4">
          Bayesian propagation &middot; Monte Carlo simulation &middot; Pareto optimization
        </p>
        <div className="flex items-center gap-1 border-b border-surface-800">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-xs font-bold transition-all relative ${
                activeTab === tab.id
                  ? 'text-white'
                  : 'text-surface-500 hover:text-surface-300'
              }`}
            >
              {tab.label}
              {activeTab === tab.id && (
                <span className="absolute bottom-0 left-0 right-0 h-[2px] bg-sage-500 rounded-t" />
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto">
        {activeTab === 'overview' && <OverviewTab />}
        {activeTab === 'schedule' && <ScheduleTab />}
        {activeTab === 'whatif' && <WhatIfTab />}
      </div>
    </div>
  )
}

// ─── Overview Tab (original BudgetView content) ──────────────
function OverviewTab() {
  const result = useAnalysisStore(s => s.result)!
  const { graph } = result

  return (
    <>
      {/* Risk Reduction Curve */}
      <div className="mb-6 animate-slideUp stagger-1">
        <RiskReductionCurve />
      </div>

      {/* Pareto Frontier */}
      <div className="mb-6 animate-slideUp stagger-2">
        <ParetoFrontier />
      </div>

      {/* Bayesian Risk Scores by Service */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
        <h3 className="text-sm font-bold text-white mb-3">Bayesian Risk Scores by Service</h3>
        <div className="grid gap-2">
          {graph.services
            .sort((a, b) => (result.riskScores[b.id] ?? 0) - (result.riskScores[a.id] ?? 0))
            .map(service => {
              const risk = result.riskScores[service.id] ?? 0
              const riskPct = Math.round(risk * 100)
              const vulnCount = graph.vulnerabilities.filter(v =>
                v.affectedServiceIds.includes(service.id)
              ).length

              return (
                <div key={service.id} className="flex items-center gap-4 bg-surface-800/30 rounded-btn p-3 transition-all duration-150 hover:bg-surface-800/60 hover:translate-x-0.5">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-bold text-white">{service.name}</span>
                      <span className="text-[10px] text-surface-600 uppercase">{service.tier}</span>
                    </div>
                    <div className="w-full h-1.5 bg-surface-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all ${
                          riskPct >= 80 ? 'bg-red-400' :
                          riskPct >= 50 ? 'bg-orange-400' :
                          riskPct >= 20 ? 'bg-amber-400' : 'bg-green-400'
                        }`}
                        style={{ width: `${riskPct}%` }}
                      />
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-sm font-bold text-white">{riskPct}%</div>
                    <div className="text-[10px] text-surface-600">{vulnCount} CVE{vulnCount !== 1 ? 's' : ''}</div>
                  </div>
                </div>
              )
            })}
        </div>
      </div>
    </>
  )
}
