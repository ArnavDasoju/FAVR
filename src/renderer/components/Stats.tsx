import { useAnalysisStore } from '../stores/analysisStore'
import BeforeAfterBar from './charts/BeforeAfterBar'

export default function Stats() {
  const result = useAnalysisStore(s => s.result)

  if (!result) {
    return (
      <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-white mb-1">Comparison</h1>
          <p className="text-sm text-surface-500">Run an analysis to compare remediation strategies</p>
        </div>
        <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card p-12 text-center">
          <p className="text-sm text-surface-500">No analysis results yet. Go to Dashboard to run an analysis.</p>
        </div>
      </div>
    )
  }

  const { simulation, graph } = result
  const optimalCurve = simulation.optimalCurve
  const naiveCurve = simulation.naiveCurve

  // Calculate savings at each step
  const savingsData = optimalCurve.map((opt, i) => {
    const naive = naiveCurve[i] ?? opt
    const saving = naive - opt
    return {
      step: i,
      saving: Math.round(saving * 1000) / 10,
      optRisk: Math.round(opt * 100),
      naiveRisk: Math.round(naive * 100),
    }
  })

  const maxSaving = Math.max(...savingsData.map(d => d.saving))
  const maxSavingStep = savingsData.find(d => d.saving === maxSaving)

  // Compare orderings
  const optimalOrder = simulation.optimalOrder
  const naiveOrder = simulation.naiveOrder

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white mb-1">Comparison</h1>
        <p className="text-sm text-surface-500">
          FAVR optimized ordering vs naive CVSS severity sort
        </p>
      </div>

      {/* Key insight */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-6">
        <div className="flex items-center gap-4">
          <div className="w-16 h-16 rounded-full bg-green-500/10 flex items-center justify-center shrink-0">
            <span className="text-2xl font-black text-green-400">{maxSaving.toFixed(1)}%</span>
          </div>
          <div>
            <div className="text-sm font-bold text-white mb-1">Maximum Risk Reduction Advantage</div>
            <p className="text-xs text-surface-400">
              At step {maxSavingStep?.step ?? 0} of {optimalCurve.length - 1} patches, FAVR's dependency-aware
              ordering achieves {maxSaving.toFixed(1)}% more risk reduction than simple CVSS severity sorting.
              This demonstrates the value of Bayesian propagation and Monte Carlo optimization.
            </p>
          </div>
        </div>
      </div>

      {/* Before/After Bar Chart */}
      <div className="mb-6">
        <BeforeAfterBar />
      </div>

      {/* Side-by-side ordering */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        {/* FAVR Optimal */}
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2 h-2 rounded-full bg-green-400" />
            <h3 className="text-sm font-bold text-white">FAVR Optimal Order</h3>
          </div>
          <div className="flex flex-col gap-1.5">
            {optimalOrder.map((vulnId, i) => {
              const vuln = graph.vulnerabilities.find(v => v.id === vulnId)
              if (!vuln) return null
              const ci = simulation.confidenceIntervals[i]
              return (
                <div key={vulnId} className="flex items-center gap-2 bg-surface-800/30 rounded-btn px-3 py-2">
                  <span className="text-[10px] font-mono text-surface-600 w-5 text-right">{i + 1}</span>
                  <SeverityDot severity={vuln.severity} />
                  <span className="text-xs text-white flex-1 truncate">{vuln.cveId}</span>
                  <span className="text-[10px] text-surface-500 font-mono">{vuln.cvssScore.toFixed(1)}</span>
                  {ci && (
                    <span className="text-[10px] text-surface-600 font-mono">{Math.round(ci.frequency * 100)}%</span>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Naive CVSS Sort */}
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2 h-2 rounded-full bg-red-400" />
            <h3 className="text-sm font-bold text-white">Naive CVSS Sort</h3>
          </div>
          <div className="flex flex-col gap-1.5">
            {naiveOrder.map((vulnId, i) => {
              const vuln = graph.vulnerabilities.find(v => v.id === vulnId)
              if (!vuln) return null
              // Check if position differs from optimal
              const optPos = optimalOrder.indexOf(vulnId)
              const diff = optPos - i
              return (
                <div key={vulnId} className="flex items-center gap-2 bg-surface-800/30 rounded-btn px-3 py-2">
                  <span className="text-[10px] font-mono text-surface-600 w-5 text-right">{i + 1}</span>
                  <SeverityDot severity={vuln.severity} />
                  <span className="text-xs text-white flex-1 truncate">{vuln.cveId}</span>
                  <span className="text-[10px] text-surface-500 font-mono">{vuln.cvssScore.toFixed(1)}</span>
                  {diff !== 0 && (
                    <span className={`text-[10px] font-mono ${diff < 0 ? 'text-green-400' : 'text-red-400'}`}>
                      {diff > 0 ? `+${diff}` : diff}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Step-by-step risk comparison table */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
        <h3 className="text-sm font-bold text-white mb-3">Step-by-Step Risk Comparison</h3>
        <div className="grid gap-1">
          {/* Header */}
          <div className="grid grid-cols-5 gap-2 px-3 py-2 text-[10px] font-bold text-surface-500 uppercase tracking-wider">
            <div>Step</div>
            <div>CVE Patched</div>
            <div className="text-right">FAVR Risk</div>
            <div className="text-right">Naive Risk</div>
            <div className="text-right">Advantage</div>
          </div>
          {savingsData.slice(1).map((row, i) => {
            const vuln = graph.vulnerabilities.find(v => v.id === optimalOrder[i])
            return (
              <div
                key={i}
                className={`grid grid-cols-5 gap-2 px-3 py-2 rounded-btn ${
                  row.saving > 0 ? 'bg-green-500/5' : ''
                }`}
              >
                <div className="text-xs text-surface-400">{row.step}</div>
                <div className="text-xs text-white truncate">{vuln?.cveId ?? '—'}</div>
                <div className="text-xs text-green-400 text-right font-mono">{row.optRisk}%</div>
                <div className="text-xs text-red-400 text-right font-mono">{row.naiveRisk}%</div>
                <div className={`text-xs text-right font-mono font-bold ${
                  row.saving > 0 ? 'text-green-400' : 'text-surface-600'
                }`}>
                  {row.saving > 0 ? `${row.saving}%` : '—'}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-400',
    high: 'bg-orange-400',
    medium: 'bg-amber-400',
    low: 'bg-blue-400',
  }
  return <div className={`w-2 h-2 rounded-full shrink-0 ${colors[severity] ?? 'bg-surface-600'}`} />
}
