import { useAnalysisStore } from '../stores/analysisStore'

type View = 'dashboard' | 'vulnerabilities' | 'analysis' | 'comparison' | 'schedule' | 'whatif' | 'settings'

interface SidebarProps {
  activeView: View
  onNavigate: (view: View) => void
}

const navItems: { id: View; label: string; shortcut: string }[] = [
  { id: 'dashboard', label: 'Dashboard', shortcut: '1' },
  { id: 'vulnerabilities', label: 'Vulnerabilities', shortcut: '2' },
  { id: 'analysis', label: 'Risk Analysis', shortcut: '3' },
  { id: 'comparison', label: 'Comparison', shortcut: '4' },
  { id: 'schedule', label: 'Schedule', shortcut: '5' },
  { id: 'whatif', label: 'What-If', shortcut: '6' },
  { id: 'settings', label: 'Settings', shortcut: '7' }
]

export default function Sidebar({ activeView, onNavigate }: SidebarProps) {
  const result = useAnalysisStore(s => s.result)
  const phase = useAnalysisStore(s => s.phase)

  const totalRisk = result
    ? Math.round(result.simulation.totalRiskBefore * 100)
    : 0
  const riskReduction = result
    ? Math.round(result.simulation.riskReduction)
    : 0
  const vulnCount = result?.graph.vulnerabilities.length ?? 0
  const criticalCount = result?.graph.vulnerabilities.filter(v => v.severity === 'critical').length ?? 0

  const riskColor = totalRisk > 70 ? 'bg-red-500' : totalRisk > 40 ? 'bg-amber-500' : 'bg-green-500'

  return (
    <div className="w-56 h-full bg-surface-950 border-r border-surface-800/50 flex flex-col transition-all">
      {/* Titlebar drag region */}
      <div className="titlebar-drag h-12 shrink-0" />

      {/* Logo */}
      <div className="px-5 pb-4">
        <span className="text-2xl font-black tracking-tight text-white">FAVR</span>
        <span className="text-[10px] text-surface-500 ml-2 font-mono">v1.0</span>
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
            <span className="text-[10px] font-mono text-surface-600">
              {item.id === 'vulnerabilities' && vulnCount > 0 ? vulnCount : ''}
              {item.id === 'analysis' && phase === 'complete' ? '✓' : ''}
            </span>
          </button>
        ))}
      </nav>

      {/* Risk summary */}
      {result && (
        <div className="px-4 pb-5">
          <div className="bg-surface-900 border border-surface-800 rounded-card p-3 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
                System Risk
              </span>
              <span className={`w-2 h-2 rounded-full ${riskColor}`} />
            </div>
            <div className="w-full h-1 bg-surface-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${riskColor}`}
                style={{ width: `${Math.min(totalRisk, 100)}%` }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-bold text-white">{totalRisk}%</span>
              <span className="text-[10px] text-green-400">-{riskReduction}%</span>
            </div>
            <div className="flex items-center justify-between mt-1">
              <span className="text-[10px] text-surface-500">{vulnCount} vulns</span>
              <span className="text-[10px] text-red-400">{criticalCount} critical</span>
            </div>
            {result.complianceSummary && result.complianceSummary.violations.some(v => v.urgentCount > 0) && (
              <div className="mt-2 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-purple-400 status-blink" />
                <span className="text-[10px] text-purple-400 font-bold">
                  {result.complianceSummary.violations.reduce((s, v) => s + v.urgentCount, 0)} urgent compliance
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

export type { View }
