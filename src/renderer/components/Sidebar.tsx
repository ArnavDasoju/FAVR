import { useAnalysisStore } from '../stores/analysisStore'

type View = 'dashboard' | 'vulnerabilities' | 'analysis' | 'comparison' | 'schedule' | 'whatif' | 'settings'

interface SidebarProps {
  activeView: View
  onNavigate: (view: View) => void
}

const navItems: { id: View; label: string; shortcut: string; icon: (active: boolean) => JSX.Element }[] = [
  {
    id: 'dashboard', label: 'Dashboard', shortcut: '1',
    icon: (a) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1h-2z" />
      </svg>
    )
  },
  {
    id: 'vulnerabilities', label: 'Vulnerabilities', shortcut: '2',
    icon: (a) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
      </svg>
    )
  },
  {
    id: 'analysis', label: 'Risk Analysis', shortcut: '3',
    icon: (a) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
      </svg>
    )
  },
  {
    id: 'comparison', label: 'Comparison', shortcut: '4',
    icon: (a) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
      </svg>
    )
  },
  {
    id: 'schedule', label: 'Schedule', shortcut: '5',
    icon: (a) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
      </svg>
    )
  },
  {
    id: 'whatif', label: 'What-If', shortcut: '6',
    icon: (a) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
    )
  },
  {
    id: 'settings', label: 'Settings', shortcut: '7',
    icon: (a) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      </svg>
    )
  },
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
  const riskTextColor = totalRisk > 70 ? 'text-red-400' : totalRisk > 40 ? 'text-amber-400' : 'text-green-400'

  return (
    <div className="w-56 h-full bg-surface-950 border-r border-surface-800/50 flex flex-col transition-all">
      {/* Titlebar drag region */}
      <div className="titlebar-drag h-12 shrink-0" />

      {/* Logo */}
      <div className="px-5 pb-4 flex items-center gap-2">
        <div className="w-7 h-7 rounded-lg bg-white flex items-center justify-center">
          <span className="text-xs font-black text-black tracking-tighter">F</span>
        </div>
        <div>
          <span className="text-lg font-black tracking-tight text-white">FAVR</span>
          <span className="text-[9px] text-surface-600 ml-1.5 font-mono">v1.0</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 flex flex-col gap-0.5">
        {navItems.map((item) => {
          const isActive = activeView === item.id
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-btn text-left transition-all duration-200 relative group ${
                isActive
                  ? 'bg-surface-800 text-white'
                  : 'text-surface-400 hover:text-white hover:bg-surface-900 hover:translate-x-0.5'
              }`}
            >
              {isActive && (
                <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 bg-white rounded-r-full animate-scaleIn" />
              )}
              <span className={`shrink-0 transition-colors ${isActive ? 'text-white' : 'text-surface-500 group-hover:text-surface-300'}`}>
                {item.icon(isActive)}
              </span>
              <span className="text-[13px] font-semibold flex-1">{item.label}</span>
              {/* Badge / indicator */}
              <span className="text-[10px] font-mono text-surface-600">
                {item.id === 'vulnerabilities' && vulnCount > 0 ? (
                  <span className="bg-surface-800 text-surface-400 px-1.5 py-0.5 rounded text-[9px] font-bold">{vulnCount}</span>
                ) : null}
                {item.id === 'analysis' && phase === 'complete' ? (
                  <svg className="w-3.5 h-3.5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                ) : null}
              </span>
            </button>
          )
        })}
      </nav>

      {/* Risk summary */}
      {result && (
        <div className="px-4 pb-5 animate-slideUp">
          <div className="bg-surface-900 border border-surface-800 rounded-card p-3 flex flex-col gap-2 card-hover">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
                System Risk
              </span>
              <span className={`text-xs font-black ${riskTextColor}`}>{totalRisk}%</span>
            </div>
            <div className="w-full h-1.5 bg-surface-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-700 ease-out ${riskColor}`}
                style={{ width: `${Math.min(totalRisk, 100)}%` }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-surface-500">{vulnCount} vuln{vulnCount !== 1 ? 's' : ''}</span>
              <span className="text-[10px] text-green-400 font-bold">-{riskReduction}% after fix</span>
            </div>
            {criticalCount > 0 && (
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 status-blink" />
                <span className="text-[10px] text-red-400 font-bold">{criticalCount} critical</span>
              </div>
            )}
            {result.complianceSummary && result.complianceSummary.violations.some(v => v.urgentCount > 0) && (
              <div className="flex items-center gap-1.5">
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
