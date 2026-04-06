import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Area, AreaChart } from 'recharts'
import { useAnalysisStore } from '../../stores/analysisStore'

export default function RiskReductionCurve() {
  const result = useAnalysisStore(s => s.result)
  if (!result) return null

  const { optimalCurve, naiveCurve, optimalOrder } = result.simulation
  const vulnMap = new Map(result.graph.vulnerabilities.map(v => [v.id, v]))

  const data = optimalCurve.map((opt, i) => ({
    step: i,
    label: i === 0 ? 'Before' : vulnMap.get(optimalOrder[i - 1])?.cveId ?? `Patch ${i}`,
    optimal: Math.round(opt * 1000) / 10,
    naive: Math.round(naiveCurve[i] * 1000) / 10,
    savings: Math.round((naiveCurve[i] - opt) * 1000) / 10
  }))

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <h3 className="text-sm font-bold text-white mb-1">Risk Reduction Curve</h3>
      <p className="text-[10px] text-surface-500 mb-3">Monte Carlo optimized vs naive severity sort</p>
      <ResponsiveContainer width="100%" height={280}>
        <AreaChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#27272A" />
          <XAxis
            dataKey="step"
            tick={{ fill: '#71717A', fontSize: 10 }}
            tickFormatter={(v) => v === 0 ? '' : `${v}`}
            label={{ value: 'Patches Applied', position: 'insideBottom', offset: -2, fill: '#71717A', fontSize: 10 }}
          />
          <YAxis
            tick={{ fill: '#71717A', fontSize: 10 }}
            tickFormatter={(v) => `${v}%`}
            domain={[0, 100]}
          />
          <Tooltip
            contentStyle={{ backgroundColor: '#18181B', border: '1px solid #3F3F46', borderRadius: '6px', fontSize: '11px' }}
            labelStyle={{ color: '#A1A1AA' }}
            formatter={(value: any, name: any) => [`${value}%`, name === 'optimal' ? 'FAVR Optimized' : 'Naive (CVSS Sort)']}
            labelFormatter={(v) => data[v]?.label ?? ''}
          />
          <Legend
            wrapperStyle={{ fontSize: '11px' }}
            formatter={(value) => value === 'optimal' ? 'FAVR Optimized' : 'Naive (CVSS Sort)'}
          />
          <Area type="monotone" dataKey="naive" stroke="#EF4444" fill="#EF444420" strokeWidth={2} dot={false} />
          <Area type="monotone" dataKey="optimal" stroke="#22C55E" fill="#22C55E20" strokeWidth={2} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
