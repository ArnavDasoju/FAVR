import { useState, useEffect, useRef } from 'react'
import { useAnalysisStore } from '../stores/analysisStore'
import DependencyGraph from './charts/DependencyGraph'
import ServiceHeatmap from './charts/ServiceHeatmap'
import SeverityDonut from './charts/SeverityDonut'
import type { AnalysisPhase } from '../../shared/types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30'
}

// ─── Phase definitions for the multi-stage progress UI ──────
interface PhaseInfo {
  id: AnalysisPhase
  label: string
  icon: string
}

const SCAN_PHASES: PhaseInfo[] = [
  { id: 'discovery',       label: 'Discovering services',              icon: '🔍' },
  { id: 'dependencies',    label: 'Mapping dependencies',              icon: '🔗' },
  { id: 'vulnerabilities', label: 'Querying vulnerability databases',  icon: '🛡' },
  { id: 'graph',           label: 'Building attack graph',             icon: '📊' },
  { id: 'bayesian',        label: 'Running Bayesian risk propagation', icon: '📈' },
  { id: 'monte-carlo',     label: 'Monte Carlo simulation',           icon: '🎲' },
  { id: 'pareto',          label: 'Computing Pareto frontier',         icon: '⚖' },
  { id: 'blast-radius',    label: 'Analyzing blast radius',            icon: '💥' },
  { id: 'scheduling',      label: 'Building patch schedule',           icon: '📅' },
  { id: 'compliance',      label: 'Checking compliance frameworks',    icon: '✓' },
]

// Map phase to its index in the pipeline
const PHASE_INDEX = new Map(SCAN_PHASES.map((p, i) => [p.id, i]))

// ─── Animated counter hook ──────────────────────────────────
function useCountUp(target: number, duration = 700): number {
  const [value, setValue] = useState(0)
  const startRef = useRef<number | null>(null)
  const targetRef = useRef(target)

  useEffect(() => {
    targetRef.current = target
    startRef.current = null
    const startValue = 0

    let raf: number
    function tick(ts: number) {
      if (startRef.current === null) startRef.current = ts
      const elapsed = ts - startRef.current
      const progress = Math.min(elapsed / duration, 1)
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setValue(Math.round(startValue + (targetRef.current - startValue) * eased))
      if (progress < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [target, duration])

  return value
}

export default function Dashboard() {
  const result = useAnalysisStore(s => s.result)
  const phase = useAnalysisStore(s => s.phase)
  const progress = useAnalysisStore(s => s.progress)
  const message = useAnalysisStore(s => s.message)
  const error = useAnalysisStore(s => s.error)
  const mode = useAnalysisStore(s => s.mode)
  const setMode = useAnalysisStore(s => s.setMode)
  const hasSeenResults = useAnalysisStore(s => s.hasSeenResults)

  const [codebasePath, setCodebasePath] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanStats, setScanStats] = useState<{ servicesFound: number; packagesScanned: number; vulnerabilitiesFound: number; ecosystems: string[] } | null>(null)

  // Track completed phases with their final messages
  const [completedPhases, setCompletedPhases] = useState<Map<string, string>>(new Map())
  const prevPhaseRef = useRef<string>('idle')

  // Track phases as they complete
  useEffect(() => {
    const currentPhase = phase
    const prevPhase = prevPhaseRef.current

    if (currentPhase !== prevPhase && prevPhase !== 'idle' && prevPhase !== 'complete' && prevPhase !== 'error') {
      // Previous phase just completed — save its final message
      setCompletedPhases(prev => {
        const next = new Map(prev)
        next.set(prevPhase, message)
        return next
      })
    }

    // If we go back to idle, clear completed phases
    if (currentPhase === 'idle') {
      setCompletedPhases(new Map())
    }

    prevPhaseRef.current = currentPhase
  }, [phase, message])

  // Auto-transition: when analysis completes, brief pause before showing results
  const [showResults, setShowResults] = useState(false)
  useEffect(() => {
    if (phase === 'complete' && result) {
      const timer = setTimeout(() => setShowResults(true), 600)
      return () => clearTimeout(timer)
    }
    if (phase === 'idle') setShowResults(false)
  }, [phase, result])

  const isRunning = phase !== 'idle' && phase !== 'complete' && phase !== 'error'

  async function handleLoadDemo() {
    setLoading(true)
    setScanStats(null)
    setCompletedPhases(new Map())
    setShowResults(false)
    try {
      await window.api.invoke('analysis:loadDemo')
    } catch (err) {
      console.error('Demo load failed:', err)
    }
    setLoading(false)
  }

  async function handleRunAnalysis() {
    const uploadedFiles = useAnalysisStore.getState().uploadedFiles
    setLoading(true)
    setScanStats(null)
    setCompletedPhases(new Map())
    setShowResults(false)
    try {
      await window.api.invoke('analysis:run', {
        filePaths: uploadedFiles.length > 0 ? uploadedFiles : undefined,
        codebasePath: mode === 'remediation' && codebasePath ? codebasePath : undefined,
        iterations: 5000
      })
    } catch (err) {
      console.error('Analysis failed:', err)
    }
    setLoading(false)
  }

  async function handleScanCodebase() {
    if (!codebasePath) return
    setLoading(true)
    setScanStats(null)
    setCompletedPhases(new Map())
    setShowResults(false)
    useAnalysisStore.getState().reset()
    try {
      const result = await window.api.invoke('analysis:analyzeCodebase', {
        codebasePath,
        iterations: 5000
      }) as { stats: typeof scanStats }
      if (result?.stats) setScanStats(result.stats)
    } catch (err) {
      console.error('Codebase scan failed:', err)
    }
    setLoading(false)
  }

  async function handleBrowseCodebase() {
    const dir = await window.api.invoke('dialog:openDirectory') as string | null
    if (dir) setCodebasePath(dir)
  }

  async function handleUploadDocs() {
    const files = await window.api.invoke('dialog:openFiles') as string[] | null
    if (files) {
      useAnalysisStore.getState().setUploadedFiles(files)
    }
  }

  // ─── No Analysis Yet — Premium Landing ─────────────────────
  if (!result && !isRunning) {
    return (
      <div className="h-full overflow-y-auto p-6 flex items-center justify-center">
        <div className="max-w-xl w-full">
          {/* Hero */}
          <div className="text-center mb-10 animate-fadeIn">
            <h1 className="text-5xl font-black text-white mb-3 tracking-tight">FAVR</h1>
            <p className="text-surface-400 text-sm max-w-md mx-auto leading-relaxed">
              Point at your codebase. Get a mathematically optimal patching plan in 30 seconds.
            </p>
          </div>

          {/* Mode Selector */}
          <div className="flex gap-3 mb-6">
            <button
              onClick={() => setMode('analysis')}
              className={`flex-1 p-5 rounded-card border text-left transition-all duration-200 card-hover animate-slideUp stagger-1 ${
                mode === 'analysis'
                  ? 'bg-surface-800 border-white/20 text-white'
                  : 'bg-surface-900 border-surface-800 text-surface-400 hover:border-surface-700'
              }`}
            >
              <div className="flex items-center gap-3 mb-2">
                <span className="text-lg">📂</span>
                <span className="text-sm font-bold">Scan Codebase</span>
              </div>
              <div className="text-[11px] text-surface-500 leading-relaxed">
                Auto-discover services, dependencies, and vulnerabilities from your project
              </div>
            </button>
            <button
              onClick={() => setMode('remediation')}
              className={`flex-1 p-5 rounded-card border text-left transition-all duration-200 card-hover animate-slideUp stagger-2 ${
                mode === 'remediation'
                  ? 'bg-surface-800 border-white/20 text-white'
                  : 'bg-surface-900 border-surface-800 text-surface-400 hover:border-surface-700'
              }`}
            >
              <div className="flex items-center gap-3 mb-2">
                <span className="text-lg">📄</span>
                <span className="text-sm font-bold">Upload Documents</span>
              </div>
              <div className="text-[11px] text-surface-500 leading-relaxed">
                Import CVE feeds, vendor advisories, or dependency maps for analysis
              </div>
            </button>
          </div>

          {/* Scan Codebase (primary flow) */}
          {mode === 'analysis' && (
            <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-5 animate-slideUp stagger-3">
              <div className="text-xs font-bold text-white mb-1">Project Directory</div>
              <p className="text-[10px] text-surface-500 mb-4">
                Supports Node.js, Python, Go, Rust, Java, and Ruby ecosystems
              </p>
              <div className="flex gap-2">
                <div className="flex-1 relative">
                  <input
                    value={codebasePath}
                    onChange={(e) => setCodebasePath(e.target.value)}
                    placeholder="Select a project folder..."
                    className="w-full bg-surface-800 border border-surface-700 rounded-btn px-3 py-2.5 text-xs text-white placeholder:text-surface-600 focus:outline-none focus:border-surface-500 transition-colors"
                  />
                </div>
                <button
                  onClick={handleBrowseCodebase}
                  className="bg-surface-800 border border-surface-700 rounded-btn px-4 py-2.5 text-xs font-bold text-surface-300 hover:bg-surface-700 hover:text-white transition-all btn-hover"
                >
                  Browse
                </button>
              </div>
              {codebasePath && (
                <div className="mt-3 flex items-center gap-2 animate-fadeIn">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                  <span className="text-[10px] text-green-400 font-mono truncate">{codebasePath}</span>
                </div>
              )}
            </div>
          )}

          {/* Document Upload (secondary flow) */}
          {mode === 'remediation' && (
            <>
              <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-4 animate-slideUp stagger-3">
                <div className="text-xs font-bold text-white mb-2">Upload Documents</div>
                <p className="text-[10px] text-surface-500 mb-3">CVE feeds, vendor advisories, dependency maps (JSON, TXT, MD)</p>
                <button
                  onClick={handleUploadDocs}
                  className="w-full border-2 border-dashed border-surface-700 rounded-btn p-6 text-surface-500 text-xs hover:border-surface-500 hover:text-surface-300 transition-colors"
                >
                  Click to upload documents
                </button>
                {useAnalysisStore.getState().uploadedFiles.length > 0 && (
                  <div className="mt-2 text-[10px] text-green-400 animate-fadeIn">
                    {useAnalysisStore.getState().uploadedFiles.length} file(s) uploaded
                  </div>
                )}
              </div>
              <div className="bg-surface-900 border border-surface-800 rounded-card p-5 mb-4 animate-slideUp stagger-4">
                <div className="text-xs font-bold text-white mb-2">Codebase Directory (optional)</div>
                <div className="flex gap-2">
                  <input
                    value={codebasePath}
                    onChange={(e) => setCodebasePath(e.target.value)}
                    placeholder="Path to your project..."
                    className="flex-1 bg-surface-800 border border-surface-700 rounded-btn px-3 py-2.5 text-xs text-white placeholder:text-surface-600 focus:outline-none focus:border-surface-500"
                  />
                  <button
                    onClick={handleBrowseCodebase}
                    className="bg-surface-800 border border-surface-700 rounded-btn px-4 py-2.5 text-xs font-bold text-surface-300 hover:bg-surface-700 transition-all btn-hover"
                  >
                    Browse
                  </button>
                </div>
              </div>
            </>
          )}

          {/* Actions */}
          <div className="flex gap-3 animate-slideUp stagger-5">
            <button
              onClick={handleLoadDemo}
              disabled={loading}
              className="bg-surface-800 border border-surface-700 text-surface-300 font-bold text-sm py-3 px-6 rounded-btn hover:bg-surface-700 disabled:opacity-50 transition-all btn-hover"
            >
              Demo
            </button>
            {mode === 'analysis' ? (
              <button
                onClick={handleScanCodebase}
                disabled={loading || !codebasePath}
                className="flex-1 bg-white text-black font-bold text-sm py-3 rounded-btn hover:bg-surface-200 disabled:opacity-50 transition-all btn-hover"
              >
                Scan Codebase
              </button>
            ) : (
              <button
                onClick={handleRunAnalysis}
                disabled={loading}
                className="flex-1 bg-white text-black font-bold text-sm py-3 rounded-btn hover:bg-surface-200 disabled:opacity-50 transition-all btn-hover"
              >
                Run Analysis
              </button>
            )}
          </div>

          {/* Supported ecosystems hint */}
          {mode === 'analysis' && (
            <div className="mt-6 flex items-center justify-center gap-4 animate-fadeIn stagger-6">
              {['Node.js', 'Python', 'Go', 'Rust', 'Java', 'Ruby'].map(eco => (
                <span key={eco} className="text-[10px] text-surface-600 font-mono">{eco}</span>
              ))}
            </div>
          )}

          {error && (
            <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded-btn p-3 text-xs text-red-400 animate-slideUp">
              {error}
            </div>
          )}
        </div>
      </div>
    )
  }

  // ─── Running — Multi-Stage Progress ────────────────────────
  if (isRunning || (phase === 'complete' && !showResults)) {
    const currentPhaseIndex = PHASE_INDEX.get(phase as AnalysisPhase) ?? -1

    return (
      <div className="h-full flex items-center justify-center">
        <div className="max-w-lg w-full px-8 animate-scaleIn">
          {/* Header */}
          <div className="text-center mb-8">
            <h2 className="text-xl font-black text-white mb-1">Analyzing</h2>
            <p className="text-xs text-surface-500">
              {codebasePath ? codebasePath.split(/[\\/]/).pop() : 'Running analysis pipeline'}
            </p>
          </div>

          {/* Phase list */}
          <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
            <div className="flex flex-col gap-1">
              {SCAN_PHASES.map((p, idx) => {
                const isComplete = currentPhaseIndex > idx || phase === 'complete'
                const isCurrent = p.id === phase
                const isPending = currentPhaseIndex < idx && phase !== 'complete'
                const completedMsg = completedPhases.get(p.id)
                // Extract a short result from the message (e.g. "Found 5 services")
                const shortResult = completedMsg ? extractShortResult(completedMsg) : null

                return (
                  <div
                    key={p.id}
                    className={`flex items-start gap-3 py-2.5 px-3 rounded-btn transition-all duration-300 ${
                      isCurrent ? 'bg-surface-800/60' : ''
                    } ${isPending ? 'opacity-30' : 'opacity-100'}`}
                    style={{
                      animationDelay: `${idx * 40}ms`
                    }}
                  >
                    {/* Status indicator */}
                    <div className="w-5 h-5 flex items-center justify-center shrink-0 mt-0.5">
                      {isComplete && (
                        <svg className="w-4 h-4 text-green-400 animate-scaleIn" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                        </svg>
                      )}
                      {isCurrent && (
                        <div className="w-3 h-3 rounded-full border-2 border-white border-t-transparent animate-spin" />
                      )}
                      {isPending && (
                        <div className="w-2 h-2 rounded-full bg-surface-700" />
                      )}
                    </div>

                    {/* Phase text */}
                    <div className="flex-1 min-w-0">
                      <div className={`text-xs font-semibold transition-colors ${
                        isComplete ? 'text-surface-300' : isCurrent ? 'text-white' : 'text-surface-600'
                      }`}>
                        {p.label}
                      </div>
                      {/* Show result summary for completed phases */}
                      {isComplete && shortResult && (
                        <div className="text-[10px] text-green-400/70 mt-0.5 animate-fadeIn truncate">
                          {shortResult}
                        </div>
                      )}
                      {/* Show live message for current phase */}
                      {isCurrent && message && (
                        <div className="text-[10px] text-surface-500 mt-0.5 animate-fadeIn" key={message}>
                          {message}
                        </div>
                      )}
                    </div>

                    {/* Progress for current phase */}
                    {isCurrent && progress > 0 && progress < 100 && (
                      <span className="text-[10px] font-mono text-surface-500 shrink-0 mt-0.5">
                        {progress}%
                      </span>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Overall progress bar */}
            <div className="mt-4 pt-4 border-t border-surface-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">Overall</span>
                <span className="text-[10px] font-mono text-surface-400">
                  {phase === 'complete' ? '100' : Math.round(((currentPhaseIndex + (progress / 100)) / SCAN_PHASES.length) * 100)}%
                </span>
              </div>
              <div className="w-full h-1.5 bg-surface-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-white rounded-full transition-all duration-500 ease-out"
                  style={{
                    width: `${phase === 'complete' ? 100 : ((currentPhaseIndex + (progress / 100)) / SCAN_PHASES.length) * 100}%`
                  }}
                />
              </div>
            </div>
          </div>

          {error && (
            <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded-btn p-3 text-xs text-red-400 animate-slideUp">
              {error}
            </div>
          )}
        </div>
      </div>
    )
  }

  // ─── Results Dashboard ─────────────────────────────────────
  const totalRisk = Math.round((result!.simulation.totalRiskBefore ?? 0) * 100)
  const reduction = Math.round(result!.simulation.riskReduction ?? 0)
  const vulnCount = result!.graph.vulnerabilities.length
  const critCount = result!.graph.vulnerabilities.filter(v => v.severity === 'critical').length
  const complianceRisk = result!.complianceSummary ? Math.round(result!.complianceSummary.overallComplianceRisk * 100) : 0
  const urgentCompliance = result!.complianceSummary?.violations.reduce((s, v) => s + v.urgentCount, 0) ?? 0
  const maxScheduleWeek = result!.schedule?.length > 0 ? Math.max(...result!.schedule.map(s => s.weekNumber)) : 0

  return (
    <ResultsDashboard
      result={result!}
      totalRisk={totalRisk}
      reduction={reduction}
      vulnCount={vulnCount}
      critCount={critCount}
      complianceRisk={complianceRisk}
      urgentCompliance={urgentCompliance}
      maxScheduleWeek={maxScheduleWeek}
      scanStats={scanStats}
      animate={!hasSeenResults}
    />
  )
}

// ─── Risk Gauge SVG ───────────────────────────────────────────
function RiskGauge({ value, size = 100, strokeWidth = 8, animate: shouldAnimate }: { value: number; size?: number; strokeWidth?: number; animate: boolean }) {
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const progress = Math.min(value, 100) / 100
  const dashOffset = circumference * (1 - progress)
  const color = value > 70 ? '#EF4444' : value > 40 ? '#F59E0B' : '#22C55E'
  const bgColor = value > 70 ? 'rgba(239,68,68,0.1)' : value > 40 ? 'rgba(245,158,11,0.1)' : 'rgba(34,197,94,0.1)'
  const grade = value > 80 ? 'F' : value > 60 ? 'D' : value > 40 ? 'C' : value > 20 ? 'B' : 'A'

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#27272A" strokeWidth={strokeWidth} />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none"
          stroke={color} strokeWidth={strokeWidth} strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={dashOffset}
          style={shouldAnimate ? { transition: 'stroke-dashoffset 1s ease-out' } : undefined}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-black text-white leading-none">{value}%</span>
        <span className="text-[9px] font-bold uppercase tracking-wider mt-0.5" style={{ color }}>{grade}</span>
      </div>
    </div>
  )
}

// ─── Results Dashboard (extracted for count-up hooks) ─────────
function ResultsDashboard({ result, totalRisk, reduction, vulnCount, critCount, complianceRisk, urgentCompliance, maxScheduleWeek, scanStats, animate }: {
  result: NonNullable<ReturnType<typeof useAnalysisStore.getState>['result']>
  totalRisk: number
  reduction: number
  vulnCount: number
  critCount: number
  complianceRisk: number
  urgentCompliance: number
  maxScheduleWeek: number
  scanStats: { servicesFound: number; packagesScanned: number; vulnerabilitiesFound: number; ecosystems: string[] } | null
  animate: boolean
}) {
  // Mark results as seen after first render
  useEffect(() => {
    if (animate) {
      const timer = setTimeout(() => useAnalysisStore.getState().markResultsSeen(), 800)
      return () => clearTimeout(timer)
    }
  }, [animate])

  // Animated counters only on first view
  const animRisk = useCountUp(animate ? totalRisk : 0, animate ? 700 : 0)
  const animReduction = useCountUp(animate ? reduction : 0, animate ? 700 : 0)
  const animVulns = useCountUp(animate ? vulnCount : 0, animate ? 700 : 0)
  const animCrit = useCountUp(animate ? critCount : 0, animate ? 700 : 0)
  const animCompliance = useCountUp(animate ? complianceRisk : 0, animate ? 700 : 0)
  const animWeeks = useCountUp(animate ? maxScheduleWeek : 0, animate ? 400 : 0)

  // Helper: only apply animation class on first view
  const a = (cls: string) => animate ? cls : ''

  const displayRisk = animate ? animRisk : totalRisk
  const displayReduction = animate ? animReduction : reduction
  const displayVulns = animate ? animVulns : vulnCount
  const displayCrit = animate ? animCrit : critCount
  const displayCompliance = animate ? animCompliance : complianceRisk
  const displayWeeks = animate ? animWeeks : maxScheduleWeek

  async function handleExport() {
    try {
      await window.api.invoke('analysis:exportReport')
    } catch (err) {
      console.error('Export failed:', err)
    }
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Scan stats banner (if came from codebase scan) */}
      {scanStats && (
        <div className={`bg-surface-900 border border-surface-800 rounded-card p-3 mb-4 flex items-center gap-6 ${a('animate-slideUp')}`}>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
            <span className="text-[10px] font-bold text-green-400">Scan Complete</span>
          </div>
          <span className="text-[10px] text-surface-500">{scanStats.servicesFound} services</span>
          <span className="text-[10px] text-surface-500">{scanStats.packagesScanned} packages</span>
          <span className="text-[10px] text-surface-500">{scanStats.vulnerabilitiesFound} vulnerabilities</span>
          <span className="text-[10px] text-surface-600 font-mono">{scanStats.ecosystems.join(', ')}</span>
        </div>
      )}

      {/* Hero Section — Risk Gauge + Key Stats */}
      <div className={`grid grid-cols-12 gap-4 mb-6 ${a('animate-slideUp stagger-1')}`}>
        {/* Risk Gauge — spans 3 cols */}
        <div className="col-span-3 bg-surface-900 border border-surface-800 rounded-card p-5 flex flex-col items-center justify-center card-hover">
          <RiskGauge value={displayRisk} size={110} strokeWidth={9} animate={animate} />
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-2 tracking-wider">System Risk</div>
        </div>

        {/* Stat cards — spans 9 cols (5 cards) */}
        <div className="col-span-9 grid grid-cols-5 gap-3">
          <div className={`bg-surface-900 border border-surface-800 rounded-card p-4 card-hover ${a('animate-slideUp stagger-2')}`}>
            <div className="flex items-center gap-1.5 mb-2">
              <svg className="w-3.5 h-3.5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
              </svg>
              <span className="text-[9px] text-surface-500 uppercase font-bold tracking-wider">Reduction</span>
            </div>
            <div className="text-2xl font-black text-green-400">-{displayReduction}%</div>
            <div className="text-[10px] text-surface-600 mt-1">after remediation</div>
          </div>

          <div className={`bg-surface-900 border border-surface-800 rounded-card p-4 card-hover ${a('animate-slideUp stagger-3')}`}>
            <div className="flex items-center gap-1.5 mb-2">
              <svg className="w-3.5 h-3.5 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z" />
              </svg>
              <span className="text-[9px] text-surface-500 uppercase font-bold tracking-wider">CVEs</span>
            </div>
            <div className="text-2xl font-black text-white">{displayVulns}</div>
            <div className="text-[10px] text-surface-600 mt-1">total found</div>
          </div>

          <div className={`bg-surface-900 border border-surface-800 rounded-card p-4 card-hover ${a('animate-slideUp stagger-4')}`}>
            <div className="flex items-center gap-1.5 mb-2">
              <div className={`w-2 h-2 rounded-full bg-red-400 ${critCount > 0 ? 'status-blink' : ''}`} />
              <span className="text-[9px] text-surface-500 uppercase font-bold tracking-wider">Critical</span>
            </div>
            <div className={`text-2xl font-black text-red-400 ${critCount > 0 ? 'animate-numberGlow' : ''}`}>{displayCrit}</div>
            <div className="text-[10px] text-surface-600 mt-1">needs attention</div>
          </div>

          <div className={`bg-surface-900 border border-surface-800 rounded-card p-4 card-hover ${a('animate-slideUp stagger-5')}`}>
            <div className="flex items-center gap-1.5 mb-2">
              <svg className="w-3.5 h-3.5 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
              <span className="text-[9px] text-surface-500 uppercase font-bold tracking-wider">Compliance</span>
            </div>
            <div className={`text-2xl font-black ${complianceRisk > 50 ? 'text-purple-400' : 'text-surface-400'}`}>{displayCompliance}%</div>
            <div className="text-[10px] text-surface-600 mt-1">compliance risk</div>
          </div>

          <div className={`bg-surface-900 border border-surface-800 rounded-card p-4 card-hover ${a('animate-slideUp stagger-6')}`}>
            <div className="flex items-center gap-1.5 mb-2">
              <svg className="w-3.5 h-3.5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
              <span className="text-[9px] text-surface-500 uppercase font-bold tracking-wider">Schedule</span>
            </div>
            <div className="text-2xl font-black text-blue-400">{displayWeeks}wk</div>
            <div className="text-[10px] text-surface-600 mt-1">to remediate</div>
          </div>
        </div>
      </div>

      {/* Compliance Alerts */}
      {urgentCompliance > 0 && (
        <div className={`bg-purple-500/10 border border-purple-500/30 rounded-card p-4 mb-6 flex items-center justify-between animate-pulseGlow ${a('animate-slideUp stagger-7')}`}>
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-purple-400 status-blink" />
            <div>
              <div className="text-sm font-bold text-purple-300">{urgentCompliance} Compliance Deadline{urgentCompliance !== 1 ? 's' : ''} Within 14 Days</div>
              <div className="text-[10px] text-purple-400/70 mt-0.5">
                {result.complianceSummary?.violations.filter(v => v.urgentCount > 0).map(v => v.framework).join(', ')}
              </div>
            </div>
          </div>
          <button
            onClick={handleExport}
            className="px-4 py-2 bg-purple-500/20 border border-purple-500/30 text-purple-300 text-xs font-bold rounded-btn hover:bg-purple-500/30 transition-colors btn-hover"
          >
            Export Report
          </button>
        </div>
      )}

      {/* Charts Grid */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className={a('animate-slideUp stagger-7')}><DependencyGraph /></div>
        <div className={a('animate-slideUp stagger-8')}><ServiceHeatmap /></div>
      </div>

      {/* Top 5 Priority Patches */}
      <div className={`bg-surface-900 border border-surface-800 rounded-card p-5 mb-6 ${a('animate-fadeIn')}`} style={animate ? { animationDelay: '400ms' } : undefined}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <svg className="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <h3 className="text-sm font-bold text-white">Top Priority Patches</h3>
            <span className="text-[9px] bg-surface-800 text-surface-400 px-2 py-0.5 rounded-full font-bold">FAVR Optimized</span>
          </div>
          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 text-[10px] font-bold text-surface-400 hover:text-white transition-colors uppercase tracking-wider btn-hover"
          >
            <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Export Report
          </button>
        </div>
        <div className="grid gap-2">
          {result.simulation.optimalOrder.slice(0, 5).map((vulnId, i) => {
            const vuln = result.graph.vulnerabilities.find(v => v.id === vulnId)
            if (!vuln) return null
            const ci = result.simulation.confidenceIntervals[i]
            const sevStyle = SEVERITY_COLORS[vuln.severity]
            const blast = result.blastRadii?.[vulnId]
            const epssDiv = Math.abs(vuln.epssScore - vuln.cvssScore / 10)
            const epssHigher = vuln.epssScore > vuln.cvssScore / 10

            return (
              <div key={vulnId} className="flex items-center gap-3 bg-surface-800/40 border border-surface-800/50 rounded-btn p-3 transition-all duration-150 hover:bg-surface-800 hover:border-surface-700 group">
                <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-black shrink-0 ${
                  i === 0 ? 'bg-white text-black' : 'bg-surface-800 text-white'
                }`}>
                  {i + 1}
                </div>
                <div className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border shrink-0 ${sevStyle}`}>
                  {vuln.severity}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-bold text-white truncate">{vuln.cveId}</span>
                    <span className="text-[10px] text-surface-500 font-mono">CVSS {vuln.cvssScore.toFixed(1)}</span>
                    {/* EPSS inline bar */}
                    <div className="flex items-center gap-1">
                      <div className="w-12 h-1 bg-surface-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${vuln.epssScore > 0.5 ? 'bg-red-400' : vuln.epssScore > 0.2 ? 'bg-amber-400' : 'bg-green-400'}`}
                          style={{ width: `${Math.min(vuln.epssScore * 100, 100)}%` }}
                        />
                      </div>
                      <span className="text-[9px] text-surface-500 font-mono">{(vuln.epssScore * 100).toFixed(0)}%</span>
                    </div>
                    {epssDiv > 0.15 && (
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${epssHigher ? 'bg-red-500/15 text-red-400' : 'bg-green-500/15 text-green-400'}`}>
                        {epssHigher ? 'HIGH EXPLOIT' : 'LOW EXPLOIT'}
                      </span>
                    )}
                  </div>
                  <span className="text-[10px] text-surface-500 truncate block">{vuln.title}</span>
                </div>
                {/* Compliance badges */}
                {vuln.complianceViolations && vuln.complianceViolations.length > 0 && (
                  <div className="flex gap-1 shrink-0">
                    {vuln.complianceViolations.slice(0, 2).map(f => (
                      <span key={f} className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-purple-500/15 text-purple-400 border border-purple-500/20">
                        {f}
                      </span>
                    ))}
                  </div>
                )}
                {/* Blast radius */}
                {blast && blast.cascadeServices.length > 0 && (
                  <div className="text-right shrink-0">
                    <div className="text-xs font-bold text-amber-400">{blast.cascadeServices.length + blast.directServices.length}</div>
                    <div className="text-[10px] text-surface-600">blast</div>
                  </div>
                )}
                <div className="text-right shrink-0">
                  <div className="text-xs font-bold text-surface-300">{Math.round(ci.frequency * 100)}%</div>
                  <div className="text-[10px] text-surface-600">confidence</div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Bottom row: Donut + Engine Stats */}
      <div className={`grid grid-cols-2 gap-4 ${a('animate-fadeIn')}`} style={animate ? { animationDelay: '500ms' } : undefined}>
        <SeverityDonut />
        <div className="bg-surface-900 border border-surface-800 rounded-card p-5 card-hover">
          <div className="flex items-center gap-2 mb-4">
            <svg className="w-4 h-4 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <h3 className="text-sm font-bold text-white">Engine Stats</h3>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-surface-800/30 rounded-btn p-3">
              <div className="text-lg font-black text-white">{result.simulation.iterations.toLocaleString()}</div>
              <div className="text-[10px] text-surface-500">MC Simulations</div>
            </div>
            <div className="bg-surface-800/30 rounded-btn p-3">
              <div className="text-lg font-black text-white">{Math.round(result.simulation.convergenceScore * 100)}%</div>
              <div className="text-[10px] text-surface-500">Convergence</div>
            </div>
            <div className="bg-surface-800/30 rounded-btn p-3">
              <div className="text-lg font-black text-white">{result.pareto.frontierIds.length}</div>
              <div className="text-[10px] text-surface-500">Pareto Solutions</div>
            </div>
            <div className="bg-surface-800/30 rounded-btn p-3">
              <div className="text-lg font-black text-white">{result.complianceSummary?.frameworks.length ?? 0}</div>
              <div className="text-[10px] text-surface-500">Frameworks Checked</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Helper: extract short result from progress message ─────
function extractShortResult(msg: string): string {
  // Already short enough
  if (msg.length <= 60) return msg
  // Try to extract the key info
  const found = msg.match(/Found \d+.*|Enriched \d+.*|Risk reduction:.*|Graph built:.*|Schedule built:.*|\d+ frameworks.*|\d+ Pareto.*|Blast radius computed.*/)
  return found ? found[0] : msg.slice(0, 60) + '...'
}
