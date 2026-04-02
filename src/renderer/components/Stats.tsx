/**
 * Stats — Weekly stats: tasks completed, hours saved, lines generated, approval rate, streak.
 */

import { useTaskStore } from '../stores/taskStore'
import { useAgentStore } from '../stores/agentStore'

export default function Stats() {
  const tasks = useTaskStore((s) => s.tasks)
  const agents = useAgentStore((s) => Object.values(s.agents))

  // Calculate stats from tasks
  const completedTasks = tasks.filter((t) => t.status === 'approved' || t.status === 'rejected')
  const approvedTasks = tasks.filter((t) => t.status === 'approved')
  const rejectedTasks = tasks.filter((t) => t.status === 'rejected')
  const totalSpent = tasks.reduce((sum, t) => sum + (t.cost ?? 0), 0)

  // Estimate hours saved (~15 min per task average)
  const hoursSaved = (completedTasks.length * 15) / 60

  // Estimate lines generated (~50 lines per subtask average)
  const linesGenerated = tasks.reduce(
    (sum, t) => sum + (t.subtasks?.length ?? 1) * 50,
    0
  )

  const approvalRate =
    completedTasks.length > 0
      ? Math.round((approvedTasks.length / completedTasks.length) * 100)
      : 0

  // Streak: count consecutive days with completed tasks (simplified)
  const streak = calculateStreak(completedTasks.map((t) => t.completedAt ?? t.createdAt))

  // Weekly breakdown
  const now = Date.now()
  const weekMs = 7 * 24 * 60 * 60 * 1000
  const weekTasks = completedTasks.filter(
    (t) => (t.completedAt ?? t.createdAt) > now - weekMs
  )

  // Agent performance
  const agentStats = new Map<string, { completed: number; approved: number }>()
  for (const task of completedTasks) {
    const model = task.model?.split('/').pop() ?? 'Auto'
    const stat = agentStats.get(model) ?? { completed: 0, approved: 0 }
    stat.completed++
    if (task.status === 'approved') stat.approved++
    agentStats.set(model, stat)
  }

  const agentPerformance = [...agentStats.entries()]
    .map(([name, stat]) => ({
      name,
      ...stat,
      rate: stat.completed > 0 ? Math.round((stat.approved / stat.completed) * 100) : 0
    }))
    .sort((a, b) => b.completed - a.completed)

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      <div className="mb-6">
        <h1 className="text-xl font-bold text-white mb-1">Stats</h1>
        <p className="text-sm text-surface-500">Your AI workforce performance</p>
      </div>

      {/* Hero stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {[
          { label: 'Tasks Done', value: String(completedTasks.length), sub: `${tasks.length} total` },
          { label: 'Hours Saved', value: `~${hoursSaved.toFixed(1)}`, sub: '15 min/task avg' },
          { label: 'Lines Generated', value: formatNumber(linesGenerated), sub: '~50/subtask' },
          { label: 'Approval Rate', value: `${approvalRate}%`, sub: `${approvedTasks.length} approved` },
          { label: 'Streak', value: `${streak}d`, sub: streak > 0 ? 'Keep it up!' : 'Submit a task' }
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

      {/* This Week */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-6">
        <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-4">
          This Week
        </span>
        <div className="grid grid-cols-4 gap-4">
          <div className="flex flex-col gap-1">
            <span className="text-lg font-bold text-white">{weekTasks.length}</span>
            <span className="text-[10px] text-surface-500">Tasks completed</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-lg font-bold text-white">
              ${weekTasks.reduce((s, t) => s + (t.cost ?? 0), 0).toFixed(2)}
            </span>
            <span className="text-[10px] text-surface-500">Spent</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-lg font-bold text-white">
              {weekTasks.filter((t) => t.status === 'approved').length}
            </span>
            <span className="text-[10px] text-surface-500">Approved</span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-lg font-bold text-white">
              {weekTasks.filter((t) => t.status === 'rejected').length}
            </span>
            <span className="text-[10px] text-surface-500">Rejected</span>
          </div>
        </div>
      </div>

      {/* Activity visualization — 7-day bar chart */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-6">
        <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-4">
          Daily Activity
        </span>
        <div className="flex items-end gap-2 h-24">
          {getLast7Days().map((day) => {
            const dayTasks = completedTasks.filter((t) => {
              const ts = t.completedAt ?? t.createdAt
              return isSameDay(ts, day.timestamp)
            })
            const maxTasks = Math.max(1, ...getLast7Days().map((d) =>
              completedTasks.filter((t) => isSameDay(t.completedAt ?? t.createdAt, d.timestamp)).length
            ))
            const height = dayTasks.length > 0 ? Math.max(8, (dayTasks.length / maxTasks) * 100) : 4

            return (
              <div key={day.label} className="flex-1 flex flex-col items-center gap-2">
                <div className="w-full flex justify-center">
                  <div
                    className={`w-full max-w-[28px] rounded-sm transition-all ${
                      dayTasks.length > 0 ? 'bg-white' : 'bg-surface-800'
                    }`}
                    style={{ height: `${height}%` }}
                  />
                </div>
                <span className="text-[9px] font-mono text-surface-600">{day.label}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Agent Performance */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
        <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-4">
          Agent Performance
        </span>
        {agentPerformance.length > 0 ? (
          <div className="flex flex-col gap-3">
            {agentPerformance.map((agent) => (
              <div key={agent.name} className="flex items-center gap-4">
                <span className="text-sm font-semibold text-white w-32 truncate">{agent.name}</span>
                <div className="flex-1 h-2 bg-surface-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-white rounded-full"
                    style={{ width: `${agent.rate}%` }}
                  />
                </div>
                <span className="text-xs font-mono text-surface-400 w-10 text-right">
                  {agent.rate}%
                </span>
                <span className="text-[10px] text-surface-600 w-16 text-right">
                  {agent.completed} tasks
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-surface-500">No agent data yet. Complete some tasks to see performance.</p>
        )}
      </div>
    </div>
  )
}

// ── Helpers ────────────────────────────────────────────────────

function calculateStreak(timestamps: number[]): number {
  if (timestamps.length === 0) return 0

  const days = new Set(timestamps.map((ts) => new Date(ts).toDateString()))
  let streak = 0
  const today = new Date()

  for (let i = 0; i < 365; i++) {
    const d = new Date(today)
    d.setDate(d.getDate() - i)
    if (days.has(d.toDateString())) {
      streak++
    } else if (i > 0) {
      break // Gap found
    }
    // i === 0 and not in set means no tasks today, but might still have yesterday
  }

  return streak
}

function formatNumber(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`
  return String(n)
}

function getLast7Days(): { label: string; timestamp: number }[] {
  const days: { label: string; timestamp: number }[] = []
  const labels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
  for (let i = 6; i >= 0; i--) {
    const d = new Date()
    d.setDate(d.getDate() - i)
    d.setHours(0, 0, 0, 0)
    days.push({ label: labels[d.getDay()], timestamp: d.getTime() })
  }
  return days
}

function isSameDay(ts: number, dayStart: number): boolean {
  const d = new Date(ts)
  d.setHours(0, 0, 0, 0)
  return d.getTime() === dayStart
}
