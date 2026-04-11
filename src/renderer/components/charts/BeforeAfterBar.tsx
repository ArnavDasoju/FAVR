import { useState, useEffect } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { useAnalysisStore } from '../../stores/analysisStore'
import { ChartSkeleton } from '../Skeleton'

export default function BeforeAfterBar() {
  const result = useAnalysisStore(s => s.result)
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setMounted(true), 100)
    return () => clearTimeout(timer)
  }, [])

  if (!result) return null
  if (!mounted) return <ChartSkeleton height={260} title="Before / After Risk" />

  const data = result.graph.services.map(service => {
    const beforeRisk = result.riskScores[service.id] ?? 0
    return {
      name: service.name.split(' ').slice(0, 2).join(' '),
      fullName: service.name,
      before: Math.round(beforeRisk * 100),
      after: 0,  // after all patches = 0
      tier: service.tier
    }
  })

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
      <h3 className="text-sm font-bold text-white mb-1">Before / After Risk by Service</h3>
      <p className="text-[10px] text-surface-500 mb-3">Risk reduction per service after full remediation</p>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#27272A" />
          <XAxis
            dataKey="name"
            tick={{ fill: '#71717A', fontSize: 10 }}
            interval={0}
          />
          <YAxis
            tick={{ fill: '#71717A', fontSize: 10 }}
            tickFormatter={(v) => `${v}%`}
            domain={[0, 100]}
          />
          <Tooltip
            contentStyle={{ backgroundColor: '#18181B', border: '1px solid #3F3F46', borderRadius: '6px', fontSize: '11px' }}
            formatter={(value: any, name: any) => [`${value}%`, name === 'before' ? 'Current Risk' : 'After Remediation']}
            labelFormatter={(_, payload) => payload?.[0]?.payload?.fullName ?? ''}
          />
          <Legend
            wrapperStyle={{ fontSize: '11px' }}
            formatter={(value) => value === 'before' ? 'Current Risk' : 'After Remediation'}
          />
          <Bar dataKey="before" fill="#EF4444" radius={[4, 4, 0, 0]} barSize={24} />
          <Bar dataKey="after" fill="#22C55E" radius={[4, 4, 0, 0]} barSize={24} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
