import { useAnalysisStore } from '../stores/analysisStore'
import { useWorkspaceStore } from '../stores/workspaceStore'

type View = 'dashboard' | 'vulnerabilities' | 'analysis' | 'workspace' | 'settings'

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
    id: 'workspace' as View, label: 'Workspace', shortcut: '4',
    icon: (a: boolean) => (
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={a ? 2.2 : 1.8}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
    )
  },
  {
    id: 'settings', label: 'Settings', shortcut: '5',
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
  const workspaceStatus = useWorkspaceStore(s => s.status)

  const totalRisk = result
    ? Math.round(result.simulation.totalRiskBefore * 100)
    : 0
  const riskReduction = result
    ? Math.round(result.simulation.riskReduction)
    : 0
  const vulnCount = result?.graph.vulnerabilities.length ?? 0
  const criticalCount = result?.graph.vulnerabilities.filter(v => v.severity === 'critical').length ?? 0

  const riskColor = totalRisk > 70 ? 'bg-[#D76B5A]' : totalRisk > 40 ? 'bg-[#E0953F]' : 'bg-sage-400'
  const riskTextColor = totalRisk > 70 ? 'text-[#E8927F]' : totalRisk > 40 ? 'text-[#EEB87B]' : 'text-sage-300'

  return (
    <div className="w-60 h-full flex flex-col relative bg-gradient-to-b from-cream-50 via-cream-100 to-cream-200 border-r border-sage-500/20">
      {/* Subtle sage glow on the right edge */}
      <div
        className="absolute top-0 right-0 w-px h-full pointer-events-none"
        style={{ background: 'linear-gradient(to bottom, transparent, rgba(130,169,104,0.35) 40%, transparent)' }}
      />

      {/* Titlebar drag region */}
      <div className="titlebar-drag h-12 shrink-0" />

      {/* Logo */}
      <div className="px-5 pb-5 flex items-center gap-2.5">
        <svg
          width="32"
          height="32"
          viewBox="0 0 32 32"
          className="shrink-0"
          aria-label="FAVR"
        >
          {/* Stem */}
          <rect x="7" y="6" width="3" height="20" fill="#405935" />
          {/* Top bar */}
          <rect x="7" y="6" width="17" height="3" fill="#405935" />
          {/* Mid bar — shorter, slightly offset */}
          <rect x="7" y="14" width="11" height="3" fill="#82a968" />
        </svg>
        <div className="flex flex-col leading-none">
          <span className="text-[17px] font-black tracking-tight text-surface-100 font-display">FAVR</span>
          <span className="text-[9px] text-sage-600 font-mono tracking-[0.2em] uppercase mt-0.5">v1.0 · sage</span>
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
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-btn text-left transition-all duration-200 relative group ${
                isActive
                  ? 'text-sage-700 bg-gradient-to-r from-sage-500/15 via-sage-500/8 to-transparent border border-sage-500/30 shadow-inner-warm'
                  : 'text-surface-200 hover:text-sage-700 hover:bg-cream-50 hover:translate-x-0.5 border border-transparent'
              }`}
            >
              {isActive && (
                <span
                  className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full animate-scaleIn"
                  style={{
                    background: 'linear-gradient(to bottom,#82a968,#405935)',
                    boxShadow: '0 0 10px rgba(106,143,84,0.55)'
                  }}
                />
              )}
              <span className={`shrink-0 transition-colors ${isActive ? 'text-sage-600' : 'text-surface-300 group-hover:text-sage-600'}`}>
                {item.icon(isActive)}
              </span>
              <span className="text-[13px] font-semibold flex-1">{item.label}</span>
              {/* Badge / indicator */}
              <span className="text-[10px] font-mono text-surface-500">
                {item.id === 'vulnerabilities' && vulnCount > 0 ? (
                  <span className="bg-cream-300 text-surface-200 px-1.5 py-0.5 rounded text-[9px] font-bold">{vulnCount}</span>
                ) : null}
                {item.id === 'workspace' && (workspaceStatus === 'running' || workspaceStatus === 'paused') ? (
                  <span className="w-2 h-2 rounded-full bg-sage-500 animate-pulse" />
                ) : null}
                {item.id === 'analysis' && phase === 'complete' ? (
                  <svg className="w-3.5 h-3.5 text-sage-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
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
          <div className="glass-card rounded-card p-3.5 flex flex-col gap-2 card-hover">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-surface-400 uppercase tracking-wider">
                System Risk
              </span>
              <span className={`text-xs font-black ${riskTextColor}`}>{totalRisk}%</span>
            </div>
            <div className="w-full h-1.5 bg-cream-300 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-700 ease-out ${riskColor}`}
                style={{ width: `${Math.min(totalRisk, 100)}%` }}
              />
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-surface-400">{vulnCount} vuln{vulnCount !== 1 ? 's' : ''}</span>
              <span className="text-[10px] text-sage-600 font-bold">-{riskReduction}% after fix</span>
            </div>
            {criticalCount > 0 && (
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#B4432E] status-blink" />
                <span className="text-[10px] text-[#B4432E] font-bold">{criticalCount} critical</span>
              </div>
            )}
            {result.complianceSummary && result.complianceSummary.violations.some(v => v.urgentCount > 0) && (
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-[#8a6fbf] status-blink" />
                <span className="text-[10px] text-[#8a6fbf] font-bold">
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
