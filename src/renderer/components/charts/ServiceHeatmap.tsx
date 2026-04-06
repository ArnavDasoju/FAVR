import { useAnalysisStore } from '../../stores/analysisStore'

const RISK_COLORS = [
  { min: 0, max: 20, bg: 'bg-green-500/20', text: 'text-green-400', label: 'Low' },
  { min: 20, max: 50, bg: 'bg-amber-500/20', text: 'text-amber-400', label: 'Medium' },
  { min: 50, max: 80, bg: 'bg-orange-500/20', text: 'text-orange-400', label: 'High' },
  { min: 80, max: 101, bg: 'bg-red-500/20', text: 'text-red-400', label: 'Critical' },
]

function getRiskStyle(score: number) {
  const pct = score * 100
  return RISK_COLORS.find(r => pct >= r.min && pct < r.max) ?? RISK_COLORS[3]
}

export default function ServiceHeatmap() {
  const result = useAnalysisStore(s => s.result)
  if (!result) return null

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <h3 className="text-sm font-bold text-white mb-1">Service Risk Heatmap</h3>
      <p className="text-[10px] text-surface-500 mb-3">Risk after Bayesian propagation</p>
      <div className="grid gap-2">
        {result.graph.services.map(service => {
          const risk = result.riskScores[service.id] ?? 0
          const style = getRiskStyle(risk)
          const vulnCount = result.graph.vulnerabilities.filter(v =>
            v.affectedServiceIds.includes(service.id)
          ).length

          return (
            <div key={service.id} className={`${style.bg} border border-surface-800 rounded-btn p-3 flex items-center justify-between`}>
              <div className="flex items-center gap-3">
                <div className={`w-2 h-8 rounded-full ${style.bg.replace('/20', '')}`} />
                <div>
                  <div className="text-xs font-bold text-white">{service.name}</div>
                  <div className="text-[10px] text-surface-500">
                    {service.tier.toUpperCase()} · {vulnCount} vuln{vulnCount !== 1 ? 's' : ''} · SLA {service.sla}%
                  </div>
                </div>
              </div>
              <div className="text-right">
                <div className={`text-lg font-black ${style.text}`}>
                  {Math.round(risk * 100)}%
                </div>
                <div className={`text-[10px] ${style.text}`}>{style.label}</div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
