import { ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { useAnalysisStore } from '../../stores/analysisStore'

export default function ParetoFrontier() {
  const result = useAnalysisStore(s => s.result)
  const selectedParetoId = useAnalysisStore(s => s.selectedParetoId)
  const selectPareto = useAnalysisStore(s => s.selectPareto)

  if (!result) return null

  const frontierSet = new Set(result.pareto.frontierIds)
  const frontierSolutions = result.pareto.solutions.filter(s => frontierSet.has(s.id))
  const dominatedSolutions = result.pareto.solutions.filter(s => !frontierSet.has(s.id))

  const frontierData = frontierSolutions.map(s => ({
    id: s.id,
    cost: s.totalCost,
    risk: Math.round(s.totalRisk * 1000) / 10,
    downtime: s.totalDowntime,
    label: s.label ?? '',
    patches: s.patchOrder.length
  }))

  const dominatedData = dominatedSolutions.slice(0, 30).map(s => ({
    id: s.id,
    cost: s.totalCost,
    risk: Math.round(s.totalRisk * 1000) / 10,
    downtime: s.totalDowntime,
    label: '',
    patches: s.patchOrder.length
  }))

  const selected = frontierSolutions.find(s => s.id === selectedParetoId)

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <h3 className="text-sm font-bold text-white mb-1">Pareto Frontier</h3>
      <p className="text-[10px] text-surface-500 mb-3">
        {frontierSolutions.length} optimal tradeoffs · Click to select
      </p>
      <ResponsiveContainer width="100%" height={280}>
        <ScatterChart margin={{ top: 5, right: 20, bottom: 20, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#27272A" />
          <XAxis
            dataKey="cost"
            type="number"
            tick={{ fill: '#71717A', fontSize: 10 }}
            label={{ value: 'Cost (person-hours)', position: 'insideBottom', offset: -10, fill: '#71717A', fontSize: 10 }}
          />
          <YAxis
            dataKey="risk"
            type="number"
            tick={{ fill: '#71717A', fontSize: 10 }}
            tickFormatter={(v) => `${v}%`}
            label={{ value: 'Residual Risk', angle: -90, position: 'insideLeft', fill: '#71717A', fontSize: 10 }}
          />
          <Tooltip
            contentStyle={{ backgroundColor: '#18181B', border: '1px solid #3F3F46', borderRadius: '6px', fontSize: '11px' }}
            formatter={(value: any, name: any) => {
              if (name === 'risk') return [`${value}%`, 'Residual Risk']
              if (name === 'cost') return [`${value} hrs`, 'Cost']
              return [value, name]
            }}
            labelFormatter={() => ''}
          />
          <Scatter name="Dominated" data={dominatedData} fill="#3F3F46" opacity={0.3}>
            {dominatedData.map((_, i) => (
              <Cell key={i} r={3} />
            ))}
          </Scatter>
          <Scatter
            name="Pareto Frontier"
            data={frontierData}
            fill="#6366F1"
            onClick={(data: any) => selectPareto(data?.id)}
            cursor="pointer"
          >
            {frontierData.map((entry) => (
              <Cell
                key={entry.id}
                fill={entry.id === selectedParetoId ? '#22C55E' : '#6366F1'}
                r={entry.id === selectedParetoId ? 8 : 5}
                stroke={entry.label ? '#fff' : 'none'}
                strokeWidth={entry.label ? 1 : 0}
              />
            ))}
          </Scatter>
        </ScatterChart>
      </ResponsiveContainer>

      {selected && (
        <div className="mt-3 bg-surface-800 rounded-btn p-3 border border-surface-700">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold text-white">{selected.label ?? 'Selected Solution'}</span>
            <span className="text-[10px] text-surface-400">{selected.patchOrder.length} patches</span>
          </div>
          <div className="grid grid-cols-3 gap-3 text-center">
            <div>
              <div className="text-lg font-black text-red-400">{Math.round(selected.totalRisk * 100)}%</div>
              <div className="text-[10px] text-surface-500">Risk</div>
            </div>
            <div>
              <div className="text-lg font-black text-amber-400">{selected.totalCost}h</div>
              <div className="text-[10px] text-surface-500">Cost</div>
            </div>
            <div>
              <div className="text-lg font-black text-blue-400">{selected.totalDowntime}m</div>
              <div className="text-[10px] text-surface-500">Downtime</div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
