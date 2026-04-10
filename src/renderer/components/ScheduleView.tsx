import { useAnalysisStore } from '../stores/analysisStore'

const DAY_COLORS: Record<string, string> = {
  Saturday: 'border-blue-500/30 bg-blue-500/5',
  Sunday: 'border-green-500/30 bg-green-500/5',
  Wednesday: 'border-amber-500/30 bg-amber-500/5',
  Any: 'border-surface-700 bg-surface-800/30'
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-500/20 border-red-500/40 text-red-400',
  high: 'bg-orange-500/20 border-orange-500/40 text-orange-400',
  medium: 'bg-amber-500/20 border-amber-500/40 text-amber-400',
  low: 'bg-blue-500/20 border-blue-500/40 text-blue-400'
}

export default function ScheduleView() {
  const result = useAnalysisStore(s => s.result)

  if (!result || !result.schedule || result.schedule.length === 0) {
    return (
      <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-white mb-1">Maintenance Schedule</h1>
          <p className="text-sm text-surface-500">Run an analysis to see the patch schedule</p>
        </div>
        <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card p-12 text-center">
          <p className="text-sm text-surface-500">No schedule available. Go to Dashboard to run an analysis.</p>
        </div>
      </div>
    )
  }

  const { schedule, graph } = result
  const vulnMap = new Map(graph.vulnerabilities.map(v => [v.id, v]))
  const serviceMap = new Map(graph.services.map(s => [s.id, s]))

  // Group by week
  const weeks = new Map<number, typeof schedule>()
  for (const patch of schedule) {
    const w = weeks.get(patch.weekNumber) ?? []
    w.push(patch)
    weeks.set(patch.weekNumber, w)
  }

  const totalCost = schedule.reduce((s, p) => {
    const vuln = vulnMap.get(p.vulnId)
    return s + (vuln?.remediationCost ?? 0)
  }, 0)
  const totalDowntime = schedule.reduce((s, p) => s + p.estimatedDuration, 0)
  const maxWeek = Math.max(...schedule.map(s => s.weekNumber))

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white mb-1">Maintenance Schedule</h1>
          <p className="text-sm text-surface-500">
            {schedule.length} patches across {maxWeek} weeks &middot; Respects maintenance windows
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className="text-sm font-bold text-white">{totalCost}h</div>
            <div className="text-[10px] text-surface-500">Total Effort</div>
          </div>
          <div className="text-right">
            <div className="text-sm font-bold text-white">{totalDowntime}m</div>
            <div className="text-[10px] text-surface-500">Total Downtime</div>
          </div>
        </div>
      </div>

      {/* Gantt Timeline */}
      <div className="flex flex-col gap-4">
        {Array.from(weeks.entries()).sort(([a], [b]) => a - b).map(([weekNum, patches]) => {
          const weekTotalDowntime = patches.reduce((s, p) => s + p.estimatedDuration, 0)

          return (
            <div key={weekNum} className="bg-surface-900 border border-surface-800 rounded-card overflow-hidden animate-slideUp" style={{ animationDelay: `${Math.min(weekNum * 80, 500)}ms` }}>
              {/* Week header */}
              <div className="px-5 py-3 border-b border-surface-800/50 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className="text-sm font-black text-white">Week {weekNum}</span>
                  <span className="text-[10px] text-surface-500">{patches.length} patch{patches.length !== 1 ? 'es' : ''}</span>
                </div>
                <span className="text-[10px] text-surface-500">{weekTotalDowntime}min downtime</span>
              </div>

              {/* Gantt bars */}
              <div className="px-5 py-3">
                {patches.map(patch => {
                  const vuln = vulnMap.get(patch.vulnId)
                  const service = serviceMap.get(patch.serviceId)
                  if (!vuln) return null

                  const windowDuration = service?.maintenanceWindow?.durationMinutes ?? 240
                  const barStart = (patch.estimatedStart / windowDuration) * 100
                  const barWidth = Math.max((patch.estimatedDuration / windowDuration) * 100, 8)
                  const sevStyle = SEVERITY_COLORS[vuln.severity]
                  const dayStyle = DAY_COLORS[patch.windowDay] ?? DAY_COLORS['Any']

                  return (
                    <div key={patch.vulnId} className="mb-3 last:mb-0">
                      {/* Info row */}
                      <div className="flex items-center gap-3 mb-1.5">
                        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded border ${sevStyle}`}>
                          {vuln.severity}
                        </span>
                        <span className="text-xs font-bold text-white">{vuln.cveId}</span>
                        <span className="text-[10px] text-surface-500 truncate flex-1">{vuln.title}</span>
                        <span className="text-[10px] text-surface-600 font-mono">{service?.name}</span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded border ${dayStyle}`}>
                          {patch.windowDay} {patch.windowStart}-{patch.windowEnd}
                        </span>
                      </div>

                      {/* Gantt bar */}
                      <div className="relative h-6 bg-surface-800 rounded-btn overflow-hidden">
                        {/* Window time markers */}
                        <div className="absolute inset-0 flex items-center">
                          {[0, 25, 50, 75].map(pct => (
                            <div key={pct} className="absolute h-full border-l border-surface-700/50" style={{ left: `${pct}%` }} />
                          ))}
                        </div>
                        {/* Patch bar */}
                        <div
                          className={`absolute h-full rounded-btn border ${sevStyle} flex items-center px-2`}
                          style={{ left: `${barStart}%`, width: `${barWidth}%`, minWidth: '60px' }}
                        >
                          <span className="text-[9px] font-bold truncate">{patch.estimatedDuration}m</span>
                        </div>
                      </div>

                      {/* Dependencies */}
                      {patch.dependsOn.length > 0 && (
                        <div className="mt-1 text-[9px] text-surface-600">
                          Depends on: {patch.dependsOn.map(id => vulnMap.get(id)?.cveId ?? id).join(', ')}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>

      {/* Legend */}
      <div className="mt-6 bg-surface-900 border border-surface-800 rounded-card p-4">
        <h3 className="text-[10px] font-bold text-surface-500 uppercase tracking-wider mb-3">Maintenance Windows</h3>
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
          {graph.services.map(service => (
            <div key={service.id} className="flex items-center gap-2 text-[10px]">
              <div className={`w-2 h-2 rounded-full ${
                service.tier === 'critical' ? 'bg-red-400' :
                service.tier === 'high' ? 'bg-orange-400' :
                service.tier === 'medium' ? 'bg-amber-400' : 'bg-blue-400'
              }`} />
              <span className="text-surface-300">{service.name}</span>
              <span className="text-surface-600 font-mono">
                {service.maintenanceWindow
                  ? `${service.maintenanceWindow.day} ${service.maintenanceWindow.startTime}-${service.maintenanceWindow.endTime}`
                  : 'Any time'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
