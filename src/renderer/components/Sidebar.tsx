import { useState } from 'react'

type View = 'dashboard' | 'agents' | 'flows' | 'budget' | 'settings'

interface SidebarProps {
  activeView: View
  onNavigate: (view: View) => void
  budget: { spent: number; limit: number }
  agentCount: number
  activeFlows: number
}

const navItems: { id: View; label: string; shortcut: string }[] = [
  { id: 'dashboard', label: 'Dashboard', shortcut: '1' },
  { id: 'agents', label: 'Agents', shortcut: '2' },
  { id: 'flows', label: 'Flows', shortcut: '3' },
  { id: 'budget', label: 'Budget', shortcut: '4' },
  { id: 'settings', label: 'Settings', shortcut: '5' }
]

export default function Sidebar({
  activeView,
  onNavigate,
  budget,
  agentCount,
  activeFlows
}: SidebarProps) {
  const budgetPercent = budget.limit > 0 ? Math.round((budget.spent / budget.limit) * 100) : 0
  const [collapsed] = useState(false)

  return (
    <div className={`${collapsed ? 'w-16' : 'w-56'} h-full bg-surface-950 border-r border-surface-800/50 flex flex-col transition-all`}>
      {/* Titlebar drag region — macOS traffic lights sit here */}
      <div className="titlebar-drag h-12 shrink-0" />

      {/* Logo */}
      <div className="px-5 pb-4">
        <span className="text-2xl font-black tracking-tight text-white">
          {collapsed ? 'B' : 'BLD'}
        </span>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 flex flex-col gap-1">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => onNavigate(item.id)}
            className={`w-full flex items-center justify-between px-3 py-2.5 rounded-btn text-left transition-colors ${
              activeView === item.id
                ? 'bg-surface-800 text-white'
                : 'text-surface-400 hover:text-white hover:bg-surface-900'
            }`}
          >
            <span className="text-sm font-semibold">{item.label}</span>
            {!collapsed && (
              <span className="text-[10px] font-mono text-surface-600">
                {item.id === 'agents' && agentCount > 0 ? agentCount : ''}
                {item.id === 'flows' && activeFlows > 0 ? activeFlows : ''}
              </span>
            )}
          </button>
        ))}
      </nav>

      {/* Budget summary */}
      {!collapsed && (
        <div className="px-4 pb-5">
          <div className="bg-surface-900 border border-surface-800 rounded-card p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
                Budget
              </span>
              <span className="text-[10px] font-mono text-surface-500">
                {budgetPercent}%
              </span>
            </div>
            <div className="w-full h-1 bg-surface-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  budgetPercent > 80 ? 'bg-surface-300' : 'bg-white'
                }`}
                style={{ width: `${Math.min(budgetPercent, 100)}%` }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-white">
                ${budget.spent.toFixed(2)}
              </span>
              <span className="text-[10px] text-surface-600">
                / ${budget.limit.toFixed(2)}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export type { View }
