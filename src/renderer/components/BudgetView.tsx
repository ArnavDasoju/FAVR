import { useAnalysisStore } from '../stores/analysisStore'
import RiskReductionCurve from './charts/RiskReductionCurve'
import ParetoFrontier from './charts/ParetoFrontier'
import SeverityDonut from './charts/SeverityDonut'

export default function BudgetView() {
  const result = useAnalysisStore(s => s.result)

  if (!result) {
    return (
      <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-white mb-1">Risk Analysis</h1>
          <p className="text-sm text-surface-500">Run an analysis to see detailed risk metrics</p>
        </div>
        <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card p-12 text-center">
          <p className="text-sm text-surface-500">No analysis results yet. Go to Dashboard to run an analysis.</p>
        </div>
      </div>
    )
  }

  const { simulation, pareto, graph } = result
  const totalRiskBefore = Math.round(simulation.totalRiskBefore * 100)
  const totalRiskAfter = Math.round(simulation.totalRiskAfter * 100)
  const riskReduction = Math.round(simulation.riskReduction)
  const totalPatchCost = graph.vulnerabilities.reduce((s, v) => s + v.remediationCost, 0)
  const totalDowntime = graph.vulnerabilities.reduce((s, v) => s + v.remediationDowntime, 0)

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white mb-1">Risk Analysis</h1>
        <p className="text-sm text-surface-500">
          Bayesian propagation &middot; Monte Carlo simulation &middot; Pareto optimization
        </p>
      </div>

      {/* Top stats */}
      <div className="grid grid-cols-5 gap-3 mb-6">
        {[
          { label: 'Risk Before', value: `${totalRiskBefore}%`, color: 'text-red-400' },
          { label: 'Risk After', value: `${totalRiskAfter}%`, color: 'text-green-400' },
          { label: 'Reduction', value: `-${riskReduction}%`, color: 'text-green-400' },
          { label: 'Total Patch Cost', value: `${totalPatchCost}h`, color: 'text-amber-400' },
          { label: 'Total Downtime', value: `${totalDowntime}m`, color: 'text-blue-400' },
        ].map(stat => (
          <div key={stat.label} className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center">
            <div className={`text-2xl font-black ${stat.color}`}>{stat.value}</div>
            <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      {/* Risk Reduction Curve */}
      <div className="mb-6">
        <RiskReductionCurve />
      </div>

      {/* Pareto + Donut side by side */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <ParetoFrontier />
        <SeverityDonut />
      </div>

      {/* Detailed Risk Scores */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-6">
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
                <div key={service.id} className="flex items-center gap-4 bg-surface-800/30 rounded-btn p-3">
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

      {/* Engine Metadata */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
        <h3 className="text-sm font-bold text-white mb-3">Simulation Metadata</h3>
        <div className="grid grid-cols-4 gap-4">
          <div>
            <div className="text-lg font-black text-white">{simulation.iterations.toLocaleString()}</div>
            <div className="text-[10px] text-surface-500">MC Iterations</div>
          </div>
          <div>
            <div className="text-lg font-black text-white">{Math.round(simulation.convergenceScore * 100)}%</div>
            <div className="text-[10px] text-surface-500">Convergence</div>
          </div>
          <div>
            <div className="text-lg font-black text-white">{pareto.frontierIds.length}</div>
            <div className="text-[10px] text-surface-500">Pareto Solutions</div>
          </div>
          <div>
            <div className="text-lg font-black text-white">{pareto.solutions.length}</div>
            <div className="text-[10px] text-surface-500">Total Candidates</div>
          </div>
        </div>
      </div>
    </div>
  )
}
