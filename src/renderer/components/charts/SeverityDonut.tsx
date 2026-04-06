import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { useAnalysisStore } from '../../stores/analysisStore'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6'
}

export default function SeverityDonut() {
  const result = useAnalysisStore(s => s.result)
  if (!result) return null

  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const v of result.graph.vulnerabilities) {
    counts[v.severity] = (counts[v.severity] ?? 0) + 1
  }

  const data = Object.entries(counts)
    .filter(([_, count]) => count > 0)
    .map(([severity, count]) => ({ name: severity, value: count }))

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <h3 className="text-sm font-bold text-white mb-1">Severity Distribution</h3>
      <p className="text-[10px] text-surface-500 mb-3">{result.graph.vulnerabilities.length} total vulnerabilities</p>
      <div className="flex items-center gap-4">
        <ResponsiveContainer width={140} height={140}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={40}
              outerRadius={65}
              dataKey="value"
              strokeWidth={2}
              stroke="#09090B"
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? '#666'} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{ backgroundColor: '#18181B', border: '1px solid #3F3F46', borderRadius: '6px', fontSize: '11px' }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="flex flex-col gap-2">
          {data.map(({ name, value }) => (
            <div key={name} className="flex items-center gap-2">
              <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: SEVERITY_COLORS[name] }} />
              <span className="text-xs text-surface-400 capitalize">{name}</span>
              <span className="text-xs font-bold text-white">{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
