import { useState, useEffect } from 'react'
import { useTaskStore } from '../stores/taskStore'
import { useAgentStore } from '../stores/agentStore'

export default function BudgetView() {
  const tasks = useTaskStore((s) => s.tasks)
  const agents = useAgentStore((s) => Object.values(s.agents))
  const [optimizationStats, setOptimizationStats] = useState({
    cacheHits: 0, cacheSaved: 0,
    contextSaved: 0,
    compressionSaved: 0,
    routingSaved: 0
  })

  // Fetch optimization stats from main process
  useEffect(() => {
    window.api.invoke('stats:optimization').then((data: unknown) => {
      if (data) setOptimizationStats(data as typeof optimizationStats)
    }).catch(() => {})
  }, [tasks.length])

  // Calculate real spend from tasks
  const spent = tasks.reduce((sum, t) => sum + (t.cost ?? 0), 0)
  const budgetLimit = 50 // TODO: make configurable
  const remaining = budgetLimit - spent
  const percent = budgetLimit > 0 ? Math.round((spent / budgetLimit) * 100) : 0

  const completedTasks = tasks.filter((t) => t.status === 'approved' || t.status === 'rejected')
  const burnRate = completedTasks.length > 0 ? spent / Math.max(1, completedTasks.length) : 0

  // Token savings
  const totalSaved = optimizationStats.cacheSaved + optimizationStats.contextSaved +
    optimizationStats.compressionSaved + optimizationStats.routingSaved
  const totalIfNoOpt = spent + totalSaved
  const savingsPercent = totalIfNoOpt > 0 ? Math.round((totalSaved / totalIfNoOpt) * 100) : 0

  const optimizations = [
    { label: 'Prompt Caching', saved: optimizationStats.cacheSaved,
      percent: totalSaved > 0 ? Math.round((optimizationStats.cacheSaved / totalSaved) * 100) : 0 },
    { label: 'Context Windowing', saved: optimizationStats.contextSaved,
      percent: totalSaved > 0 ? Math.round((optimizationStats.contextSaved / totalSaved) * 100) : 0 },
    { label: 'Conversation Compression', saved: optimizationStats.compressionSaved,
      percent: totalSaved > 0 ? Math.round((optimizationStats.compressionSaved / totalSaved) * 100) : 0 },
    { label: 'Free-First Routing', saved: optimizationStats.routingSaved,
      percent: totalSaved > 0 ? Math.round((optimizationStats.routingSaved / totalSaved) * 100) : 0 }
  ]

  // Agent spend breakdown
  const agentSpend = new Map<string, number>()
  for (const agent of agents) {
    agentSpend.set(agent.name, 0)
  }
  // Aggregate from tasks
  for (const task of tasks) {
    const model = task.model?.split('/').pop() ?? 'Auto'
    agentSpend.set(model, (agentSpend.get(model) ?? 0) + (task.cost ?? 0))
  }
  const agentBreakdown = [...agentSpend.entries()]
    .map(([name, s]) => ({ name, spent: s, percent: spent > 0 ? Math.round((s / spent) * 100) : 0 }))
    .sort((a, b) => b.spent - a.spent)

  // Recent activity from completed tasks
  const recentActivity = [...completedTasks]
    .sort((a, b) => (b.completedAt ?? 0) - (a.completedAt ?? 0))
    .slice(0, 8)
    .map((t) => ({
      date: formatTimeAgo(t.completedAt ?? t.createdAt),
      agent: t.model?.split('/').pop() ?? 'Auto',
      task: t.prompt,
      cost: t.cost ?? 0
    }))

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white mb-1">Budget</h1>
        <p className="text-sm text-surface-500">
          Portfolio allocation &middot; Optimize spend across your agent roster
        </p>
      </div>

      {/* Top stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Spent', value: `$${spent.toFixed(2)}`, sub: `${percent}% of budget` },
          { label: 'Remaining', value: `$${remaining.toFixed(2)}`, sub: `$${budgetLimit} limit` },
          { label: 'Tasks Done', value: `${completedTasks.length}`, sub: `${tasks.length} total` },
          { label: 'Saved', value: `$${totalSaved.toFixed(2)}`, sub: totalSaved > 0 ? `${savingsPercent}% reduction` : 'no tasks yet' }
        ].map((stat) => (
          <div
            key={stat.label}
            className="bg-surface-900 border border-surface-800 rounded-card p-4 flex flex-col gap-1"
          >
            <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
              {stat.label}
            </span>
            <span className="text-2xl font-bold text-white">{stat.value}</span>
            <span className="text-[11px] text-surface-500">{stat.sub}</span>
          </div>
        ))}
      </div>

      {/* Budget bar */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-6">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-bold text-white">Monthly Budget</span>
          <span className="text-sm font-mono text-surface-400">
            ${spent.toFixed(2)} / ${budgetLimit.toFixed(2)}
          </span>
        </div>
        <div className="w-full h-3 bg-surface-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${
              percent > 80 ? 'bg-surface-300' : 'bg-white'
            }`}
            style={{ width: `${Math.min(percent, 100)}%` }}
          />
        </div>
      </div>

      {/* Token Savings */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-6">
        <div className="flex items-center justify-between mb-4">
          <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em]">
            Token Optimization
          </span>
          <span className="text-sm font-bold text-white">${totalSaved.toFixed(2)} saved</span>
        </div>

        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
          {optimizations.map((opt) => (
            <div key={opt.label} className="flex flex-col gap-2">
              <span className="text-[10px] text-surface-500 font-semibold">{opt.label}</span>
              <div className="flex items-baseline gap-1.5">
                <span className="text-lg font-bold text-white">${opt.saved.toFixed(2)}</span>
                <span className="text-[10px] font-mono text-surface-600">{opt.percent}%</span>
              </div>
              <div className="w-full h-1 bg-surface-800 rounded-full overflow-hidden">
                <div className="h-full bg-white rounded-full" style={{ width: `${opt.percent}%` }} />
              </div>
            </div>
          ))}
        </div>

        {totalSaved > 0 && (
          <div className="flex items-center gap-3 pt-3 border-t border-surface-800/50">
            <span className="text-xs text-surface-500">
              Without BLD you&apos;d have spent <span className="text-white font-bold">${totalIfNoOpt.toFixed(2)}</span>
            </span>
            <span className="text-xs text-surface-600">&middot;</span>
            <span className="text-xs text-surface-500">
              BLD saved you <span className="text-white font-bold">{savingsPercent}%</span>
            </span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Agent breakdown */}
        <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
          <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-4">
            Spend by Agent
          </span>
          {agentBreakdown.length > 0 ? (
            <div className="flex flex-col gap-4">
              {agentBreakdown.map((agent) => (
                <div key={agent.name} className="flex flex-col gap-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-white">{agent.name}</span>
                    <span className="text-sm font-mono text-surface-400">
                      {agent.spent === 0 ? 'Free' : `$${agent.spent.toFixed(2)}`}
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-surface-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-white rounded-full"
                      style={{ width: `${agent.percent}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-surface-500">No agent spend data yet.</p>
          )}
        </div>

        {/* Recent activity */}
        <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
          <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-4">
            Recent Activity
          </span>
          {recentActivity.length > 0 ? (
            <div className="flex flex-col gap-0">
              {recentActivity.map((entry, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 py-2.5 border-b border-surface-800/30 last:border-0"
                >
                  <span className="text-[10px] text-surface-600 w-16 shrink-0">{entry.date}</span>
                  <span className="text-xs text-surface-400 flex-1 truncate">{entry.task}</span>
                  <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider shrink-0">
                    {entry.agent}
                  </span>
                  <span className="text-xs font-mono text-white w-12 text-right shrink-0">
                    ${entry.cost.toFixed(2)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-surface-500">No activity yet. Complete some tasks to see spend history.</p>
          )}
        </div>
      </div>
    </div>
  )
}

function formatTimeAgo(timestamp: number): string {
  const diff = Date.now() - timestamp
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days === 1) return 'Yesterday'
  return `${days}d ago`
}
