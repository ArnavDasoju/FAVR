import { useState, useEffect, useRef, useCallback } from 'react'
import { useAnalysisStore } from '../stores/analysisStore'
import { useAgentStore } from '../stores/agentStore'
import DependencyGraph from './charts/DependencyGraph'
import SeverityDonut from './charts/SeverityDonut'
import MonteCarloViz from './MonteCarloViz'
import type { AnalysisPhase } from '../../shared/types'

// ─── Fix-All session types ──────────────────────────────────
type FixPhase = 'idle' | 'patching' | 'done'

interface FixVulnRow {
  index: number
  cveId: string
  title: string
  affectedPackage: string
  patchedVersion: string
  severity: string
  complexity: 'low' | 'medium' | 'high'
  model: string
  displayName: string
  provider: string
  taskType: string
  reasoning: string
  status: 'pending' | 'running' | 'done' | 'failed'
  agentId: string | null
  changedFiles: string[]
  error: string | null
}

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
}

const SCAN_PHASES: PhaseInfo[] = [
  { id: 'discovery',       label: 'Discovering services' },
  { id: 'docker',          label: 'Scanning Docker images' },
  { id: 'dependencies',    label: 'Mapping dependencies' },
  { id: 'vulnerabilities', label: 'Querying vulnerability databases' },
  { id: 'graph',           label: 'Building attack graph' },
  { id: 'bayesian',        label: 'Running Bayesian risk propagation' },
  { id: 'monte-carlo',     label: 'Monte Carlo simulation' },
  { id: 'pareto',          label: 'Computing Pareto frontier' },
  { id: 'blast-radius',    label: 'Analyzing blast radius' },
  { id: 'scheduling',      label: 'Building patch schedule' },
  { id: 'compliance',      label: 'Checking compliance frameworks' },
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

export default function Dashboard({ onOpenWorkspace }: { onOpenWorkspace?: (codebasePath: string) => void }) {
  const result = useAnalysisStore(s => s.result)
  const phase = useAnalysisStore(s => s.phase)
  const progress = useAnalysisStore(s => s.progress)
  const message = useAnalysisStore(s => s.message)
  const error = useAnalysisStore(s => s.error)
  const mode = useAnalysisStore(s => s.mode)
  const setMode = useAnalysisStore(s => s.setMode)
  const hasSeenResults = useAnalysisStore(s => s.hasSeenResults)

  const uploadedFiles = useAnalysisStore(s => s.uploadedFiles)
  const codebasePath = useAnalysisStore(s => s.codebasePath)
  const setCodebasePath = useAnalysisStore(s => s.setCodebasePath)
  const [loading, setLoading] = useState(false)
  const [scanStats, setScanStats] = useState<{ servicesFound: number; packagesScanned: number; vulnerabilitiesFound: number; ecosystems: string[]; unresolvedPackages?: number; dockerImagesScanned?: number; isMonorepo?: boolean; scanDurationMs?: number } | null>(null)
  const [riskModel, setRiskModel] = useState<'conservative' | 'balanced' | 'aggressive'>('balanced')
  const [scanHistory, setScanHistory] = useState<Array<{ id: string; projectPath: string; projectName: string; timestamp: number; durationMs: number; stats: any }>>([])
  const [showHistory, setShowHistory] = useState(false)

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
      await window.api.invoke('analysis:setRiskModel', riskModel)
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
      await window.api.invoke('analysis:setRiskModel', riskModel)
      await window.api.invoke('analysis:run', {
        filePaths: uploadedFiles.length > 0 ? uploadedFiles : undefined,
        codebasePath: mode === 'remediation' && codebasePath ? codebasePath : undefined
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
    await window.api.invoke('analysis:setRiskModel', riskModel)
    try {
      const result = await window.api.invoke('analysis:analyzeCodebase', {
        codebasePath
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

  function handleExitToHome() {
    useAnalysisStore.getState().reset()
    useAnalysisStore.getState().setUploadedFiles([])
    setCodebasePath('')
    setScanStats(null)
    setShowResults(false)
    setCompletedPhases(new Map())
    setLoading(false)
  }

  // Load scan history on mount
  const loadHistory = useCallback(async () => {
    try {
      const history = await window.api.invoke('scanHistory:list') as typeof scanHistory
      setScanHistory(history ?? [])
    } catch { /* ignore */ }
  }, [])

  useEffect(() => { loadHistory() }, [loadHistory])

  async function handleLoadScan(scanId: string) {
    setLoading(true)
    setShowResults(false)
    try {
      const result = await window.api.invoke('scanHistory:load', scanId) as any
      if (result?.stats) setScanStats(result.stats)
      setShowResults(true)
    } catch (err) {
      console.error('Failed to load scan:', err)
    }
    setLoading(false)
  }

  async function handleDeleteScan(scanId: string) {
    try {
      await window.api.invoke('scanHistory:delete', scanId)
      loadHistory()
    } catch { /* ignore */ }
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
                <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
                </svg>
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
                <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
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
                  {uploadedFiles.length > 0 ? 'Click to upload more documents' : 'Click to upload documents'}
                </button>
                {uploadedFiles.length > 0 && (
                  <div className="mt-3 flex flex-col gap-1.5 animate-fadeIn">
                    {uploadedFiles.map((f, i) => (
                      <div key={i} className="flex items-center gap-2 text-[10px]">
                        <span className="text-green-400">+</span>
                        <span className="text-surface-300 font-mono truncate">{f.split(/[\\/]/).pop()}</span>
                      </div>
                    ))}
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

          {/* Risk Model Selector */}
          <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-5 animate-slideUp stagger-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs font-bold text-white mb-0.5">Risk Model</div>
                <div className="text-[10px] text-surface-500">Controls how unknown factors and edge cases are weighted</div>
              </div>
              <div className="flex gap-1.5">
                {(['conservative', 'balanced', 'aggressive'] as const).map(model => (
                  <button
                    key={model}
                    onClick={() => setRiskModel(model)}
                    className={`px-3 py-1.5 rounded-btn text-[10px] font-bold transition-all ${
                      riskModel === model
                        ? model === 'conservative' ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                          : model === 'balanced' ? 'bg-indigo-500/15 text-indigo-400 border border-indigo-500/30'
                          : 'bg-green-500/15 text-green-400 border border-green-500/30'
                        : 'bg-surface-800 text-surface-500 border border-surface-700 hover:text-surface-300'
                    }`}
                  >
                    {model.charAt(0).toUpperCase() + model.slice(1)}
                  </button>
                ))}
              </div>
            </div>
          </div>

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
              {['Node.js', 'Python', 'Go', 'Rust', 'Java', 'Ruby', 'Docker'].map(eco => (
                <span key={eco} className="text-[10px] text-surface-600 font-mono">{eco}</span>
              ))}
            </div>
          )}

          {error && (
            <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded-btn p-3 text-xs text-red-400 animate-slideUp">
              {error}
            </div>
          )}

          {/* Scan History */}
          {scanHistory.length > 0 && (
            <div className="mt-6 animate-fadeIn">
              <button
                onClick={() => setShowHistory(!showHistory)}
                className="w-full flex items-center justify-between text-xs text-surface-500 hover:text-surface-300 transition-colors mb-2 px-1"
              >
                <span className="font-bold">Recent Scans ({scanHistory.length})</span>
                <span className="text-[10px]">{showHistory ? 'Hide' : 'Show'}</span>
              </button>
              {showHistory && (
                <div className="bg-surface-900 border border-surface-800 rounded-card overflow-hidden">
                  {scanHistory.slice(0, 10).map((scan) => (
                    <div
                      key={scan.id}
                      className="flex items-center gap-3 px-4 py-3 border-b border-surface-800 last:border-b-0 hover:bg-surface-800/50 transition-colors group"
                    >
                      <div className="flex-1 min-w-0 cursor-pointer" onClick={() => handleLoadScan(scan.id)}>
                        <div className="text-xs text-white font-medium truncate">{scan.projectName}</div>
                        <div className="text-[10px] text-surface-500 flex items-center gap-2 mt-0.5">
                          <span>{new Date(scan.timestamp).toLocaleDateString()}</span>
                          <span>·</span>
                          <span>{scan.stats?.vulnerabilitiesFound ?? 0} vulns</span>
                          <span>·</span>
                          <span>{scan.stats?.servicesFound ?? 0} services</span>
                          {scan.durationMs > 0 && (
                            <>
                              <span>·</span>
                              <span>{(scan.durationMs / 1000).toFixed(1)}s</span>
                            </>
                          )}
                        </div>
                      </div>
                      <button
                        onClick={(e) => { e.stopPropagation(); handleDeleteScan(scan.id) }}
                        className="text-surface-600 hover:text-red-400 text-[10px] opacity-0 group-hover:opacity-100 transition-opacity"
                        title="Delete scan"
                      >
                        x
                      </button>
                    </div>
                  ))}
                </div>
              )}
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
      <div className="h-full flex flex-col overflow-auto py-6">
        <div className="px-8 mb-2">
          <button
            onClick={handleExitToHome}
            className="flex items-center gap-2 text-xs text-surface-500 hover:text-white transition-colors group"
          >
            <svg className="w-4 h-4 group-hover:-translate-x-0.5 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
            </svg>
            <span className="font-medium">Cancel &amp; Start Over</span>
          </button>
        </div>
        <div className="flex-1 flex items-center justify-center">
        <div className="max-w-3xl w-full px-8 animate-scaleIn">
          {/* Header */}
          <div className="text-center mb-6">
            <h2 className="text-2xl font-black text-white mb-1 font-display">Analyzing</h2>
            <p className="text-xs text-surface-500">
              {codebasePath ? codebasePath.split(/[\\/]/).pop() : 'Running analysis pipeline'}
            </p>
          </div>

          {/* Monte Carlo live visualization */}
          <div className="mb-5 animate-slideUp">
            <MonteCarloViz />
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
      </div>
    )
  }

  // ─── Results Dashboard ─────────────────────────────────────
  const totalRisk = Math.round((result!.simulation.totalRiskBefore ?? 0) * 100)
  const vulnCount = result!.graph.vulnerabilities.length
  const urgentCompliance = result!.complianceSummary?.violations.reduce((s, v) => s + v.urgentCount, 0) ?? 0

  return (
    <ResultsDashboard
      result={result!}
      totalRisk={totalRisk}
      vulnCount={vulnCount}
      urgentCompliance={urgentCompliance}
      scanStats={scanStats}
      codebasePath={codebasePath}
      onExit={handleExitToHome}
      onOpenWorkspace={onOpenWorkspace}
      animate={!hasSeenResults}
    />
  )
}

// ─── Results Dashboard (extracted for count-up hooks) ─────────
function ResultsDashboard({ result, totalRisk, vulnCount, urgentCompliance, scanStats, codebasePath, onExit, onOpenWorkspace, animate }: {
  result: NonNullable<ReturnType<typeof useAnalysisStore.getState>['result']>
  totalRisk: number
  vulnCount: number
  urgentCompliance: number
  scanStats: { servicesFound: number; packagesScanned: number; vulnerabilitiesFound: number; ecosystems: string[]; unresolvedPackages?: number; dockerImagesScanned?: number; isMonorepo?: boolean; scanDurationMs?: number } | null
  codebasePath: string
  onExit: () => void
  onOpenWorkspace?: (codebasePath: string) => void
  animate: boolean
}) {
  // Mark results as seen after first render
  useEffect(() => {
    if (animate) {
      const timer = setTimeout(() => useAnalysisStore.getState().markResultsSeen(), 800)
      return () => clearTimeout(timer)
    }
  }, [animate])

  // Helper: only apply animation class on first view
  const a = (cls: string) => animate ? cls : ''

  const [exporting, setExporting] = useState(false)
  const [exported, setExported] = useState(false)
  const [dataFreshness, setDataFreshness] = useState<Record<string, { name: string; lastQueried: number | null; available: boolean; entriesReturned: number; error?: string }> | null>(null)
  const [clearingCache, setClearingCache] = useState(false)

  // Load data freshness from result or IPC
  useEffect(() => {
    if (result?.dataFreshness) {
      setDataFreshness(result.dataFreshness)
    } else {
      window.api.invoke('vuln:getFreshness').then((f: any) => {
        if (f) setDataFreshness(f)
      }).catch(() => {})
    }
  }, [result])

  async function handleClearCache() {
    setClearingCache(true)
    try {
      await window.api.invoke('vuln:clearCache')
      setDataFreshness(null)
    } catch { /* ignore */ }
    setClearingCache(false)
  }

  // ─── Fix-All session state ───────────────────────────────────
  const [fixPhase, setFixPhase] = useState<FixPhase>('idle')
  const [fixVulns, setFixVulns] = useState<FixVulnRow[]>([])
  const [fixCanUndo, setFixCanUndo] = useState(false)
  const [undoing, setUndoing] = useState(false)
  const [rescanning, setRescanning] = useState(false)
  const agents = useAgentStore(s => s.agents)

  useEffect(() => {
    const unsubs: (() => void)[] = []

    unsubs.push(window.api.on('fix:started', (data: unknown) => {
      const { canUndo } = data as { total: number; canUndo: boolean }
      setFixPhase('patching')
      setFixCanUndo(canUndo)
    }))

    unsubs.push(window.api.on('fix:vulnStart', (data: unknown) => {
      const d = data as {
        index: number; cveId: string; title: string; affectedPackage: string
        patchedVersion: string; severity: string; complexity: 'low' | 'medium' | 'high'; model: string
        displayName?: string; provider?: string; taskType?: string; reasoning?: string
      }
      setFixVulns(prev => {
        const next = [...prev]
        while (next.length <= d.index) {
          next.push({
            index: next.length, cveId: '', title: '', affectedPackage: '', patchedVersion: '',
            severity: 'low', complexity: 'low', model: '', displayName: '', provider: '',
            taskType: '', reasoning: '', status: 'pending',
            agentId: null, changedFiles: [], error: null
          })
        }
        next[d.index] = {
          ...next[d.index],
          index: d.index,
          cveId: d.cveId,
          title: d.title,
          affectedPackage: d.affectedPackage,
          patchedVersion: d.patchedVersion,
          severity: d.severity,
          complexity: d.complexity,
          model: d.model,
          displayName: d.displayName ?? d.model.split('/').pop() ?? d.model,
          provider: d.provider ?? '',
          taskType: d.taskType ?? '',
          reasoning: d.reasoning ?? '',
          status: 'running'
        }
        return next
      })
    }))

    unsubs.push(window.api.on('fix:vulnDone', (data: unknown) => {
      const d = data as {
        index: number; cveId: string; success: boolean; agentId?: string
        changedFiles?: string[]; error?: string
      }
      setFixVulns(prev => {
        const next = [...prev]
        if (next[d.index]) {
          next[d.index] = {
            ...next[d.index],
            status: d.success ? 'done' : 'failed',
            agentId: d.agentId ?? null,
            changedFiles: d.changedFiles ?? [],
            error: d.error ?? null
          }
        }
        return next
      })
    }))

    unsubs.push(window.api.on('fix:complete', (data: unknown) => {
      const d = data as { succeeded: number; failed: number; canUndo: boolean }
      setFixPhase('done')
      setFixCanUndo(d.canUndo)
    }))

    return () => { for (const u of unsubs) u() }
  }, [])

  async function handleFixAll() {
    if (!codebasePath) {
      console.error('No codebase path — cannot fix')
      return
    }
    setFixVulns([])
    setFixPhase('patching')
    try {
      await window.api.invoke('fix:all', { codebasePath })
    } catch (err) {
      console.error('fix:all failed:', err)
      setFixPhase('done')
    }
  }

  async function handleUndo() {
    setUndoing(true)
    try {
      await window.api.invoke('fix:undo')
      setFixPhase('idle')
      setFixVulns([])
      setFixCanUndo(false)
    } catch (err) {
      console.error('fix:undo failed:', err)
    }
    setUndoing(false)
  }

  async function handleRescan() {
    if (!codebasePath) return
    setRescanning(true)
    try {
      useAnalysisStore.getState().reset()
      await window.api.invoke('analysis:analyzeCodebase', { codebasePath })
      setFixPhase('idle')
      setFixVulns([])
    } catch (err) {
      console.error('rescan failed:', err)
    }
    setRescanning(false)
  }

  async function handleExport() {
    setExporting(true)
    try {
      const path = await window.api.invoke('analysis:exportReport')
      if (path) {
        setExported(true)
        setTimeout(() => setExported(false), 3000)
      }
    } catch (err) {
      console.error('Export failed:', err)
    }
    setExporting(false)
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Top bar with exit button */}
      <div className={`flex items-center justify-between mb-4 ${a('animate-fadeIn')}`}>
        <button
          onClick={onExit}
          className="flex items-center gap-2 text-xs text-surface-500 hover:text-white transition-colors group"
        >
          <svg className="w-4 h-4 group-hover:-translate-x-0.5 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          <span className="font-medium">New Analysis</span>
        </button>
        <span className="text-[10px] text-surface-600 font-mono">{codebasePath ? codebasePath.split(/[\\/]/).pop() : 'FAVR Analysis'}</span>
      </div>

      {/* Scan stats banner (if came from codebase scan) */}
      {scanStats && (
        <div className={`bg-surface-900 border border-surface-800 rounded-card p-3 mb-4 flex items-center gap-4 flex-wrap ${a('animate-slideUp')}`}>
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
            <span className="text-[10px] font-bold text-green-400">Scan Complete</span>
          </div>
          <span className="text-[10px] text-surface-500">{scanStats.servicesFound} services{scanStats.isMonorepo ? ' (monorepo)' : ''}</span>
          <span className="text-[10px] text-surface-500">{scanStats.packagesScanned} packages</span>
          <span className="text-[10px] text-surface-500">{scanStats.vulnerabilitiesFound} vulnerabilities</span>
          {(scanStats.unresolvedPackages ?? 0) > 0 && (
            <span className="text-[10px] text-surface-600">{scanStats.unresolvedPackages} private/skipped</span>
          )}
          {(scanStats.dockerImagesScanned ?? 0) > 0 && (
            <span className="text-[10px] text-surface-500">{scanStats.dockerImagesScanned} Docker images</span>
          )}
          <span className="text-[10px] text-surface-600 font-mono">{scanStats.ecosystems.join(', ')}</span>
          {(scanStats.scanDurationMs ?? 0) > 0 && (
            <span className="text-[10px] text-surface-600">{((scanStats.scanDurationMs ?? 0) / 1000).toFixed(1)}s</span>
          )}
        </div>
      )}

      {/* Data Freshness Indicator */}
      {dataFreshness && (
        <div className={`bg-surface-900 border border-surface-800 rounded-card p-3 mb-4 ${a('animate-slideUp')}`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <svg className="w-3.5 h-3.5 text-surface-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              <span className="text-[10px] font-bold text-surface-400 uppercase tracking-wider">Data Sources</span>
            </div>
            <button
              onClick={handleClearCache}
              disabled={clearingCache}
              className="text-[9px] text-surface-600 hover:text-surface-300 transition-colors disabled:opacity-50"
            >
              {clearingCache ? 'Clearing...' : 'Clear Cache'}
            </button>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            {Object.entries(dataFreshness).map(([key, src]) => {
              const source = src as { name: string; lastQueried: number | null; available: boolean; entriesReturned: number; error?: string }
              const age = source.lastQueried ? Date.now() - source.lastQueried : null
              const ageText = age === null ? 'never'
                : age < 60_000 ? 'just now'
                : age < 3600_000 ? `${Math.round(age / 60_000)}m ago`
                : age < 86400_000 ? `${Math.round(age / 3600_000)}h ago`
                : `${Math.round(age / 86400_000)}d ago`
              const isStale = age !== null && age > 7 * 86400_000
              const hasData = source.entriesReturned > 0
              const dotColor = !source.available || source.error ? 'bg-red-400'
                : isStale ? 'bg-amber-400'
                : hasData ? 'bg-green-400'
                : 'bg-surface-600'
              const textColor = !source.available || source.error ? 'text-red-400'
                : isStale ? 'text-amber-400'
                : hasData ? 'text-surface-300'
                : 'text-surface-600'

              return (
                <div key={key} className="flex items-center gap-1.5" title={source.error ?? `${source.entriesReturned} entries`}>
                  <div className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
                  <span className={`text-[10px] font-medium ${textColor}`}>{source.name}</span>
                  <span className="text-[9px] text-surface-600 font-mono">{ageText}</span>
                  {isStale && <span className="text-[8px] text-amber-400 font-bold">STALE</span>}
                </div>
              )
            })}
          </div>
        </div>
      )}

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
            disabled={exporting}
            className="px-4 py-2 bg-purple-500/20 border border-purple-500/30 text-purple-300 text-xs font-bold rounded-btn hover:bg-purple-500/30 transition-colors btn-hover disabled:opacity-50 flex items-center gap-1.5"
          >
            {exporting && <div className="w-3 h-3 rounded-full border border-purple-400 border-t-transparent animate-spin" />}
            {exported ? 'Saved' : exporting ? 'Exporting...' : 'Export Report'}
          </button>
        </div>
      )}

      {/* Fix-All Panel — shown while patching or after completion */}
      {fixPhase !== 'idle' && (
        <FixAllPanel
          phase={fixPhase}
          vulns={fixVulns}
          agents={agents}
          canUndo={fixCanUndo}
          undoing={undoing}
          rescanning={rescanning}
          onUndo={handleUndo}
          onRescan={handleRescan}
          onDismiss={() => setFixPhase('idle')}
        />
      )}

      {/* Dependency graph — full width so the map has room to breathe */}
      <div className={`${a('animate-slideUp stagger-7')} mb-4`}>
        <DependencyGraph />
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
          <div className="flex items-center gap-3">
            {onOpenWorkspace && (
              <button
                onClick={() => onOpenWorkspace(codebasePath)}
                disabled={!codebasePath || vulnCount === 0}
                className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-btn bg-sage-500/15 border border-sage-500/40 text-sage-200 hover:bg-sage-500/25 hover:border-sage-500/60 transition-all btn-hover disabled:opacity-40 disabled:cursor-not-allowed"
                title={codebasePath ? 'Open Remediation Workspace with budget optimization' : 'Scan a codebase first'}
              >
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                Workspace
              </button>
            )}
            <button
              onClick={handleFixAll}
              disabled={fixPhase === 'patching' || !codebasePath || vulnCount === 0}
              className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-btn bg-green-500/10 border border-green-500/40 text-green-300 hover:bg-green-500/20 hover:border-green-500/60 transition-all btn-hover disabled:opacity-40 disabled:cursor-not-allowed"
              title={codebasePath ? 'Quick fix all (sequential, no budget control)' : 'Scan a codebase first'}
            >
              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              {fixPhase === 'patching' ? 'Patching...' : 'Quick Fix'}
            </button>
          <button
            onClick={handleExport}
            disabled={exporting}
            className={`flex items-center gap-1.5 text-[10px] font-bold transition-colors uppercase tracking-wider btn-hover ${
              exported ? 'text-green-400' : exporting ? 'text-surface-600' : 'text-surface-400 hover:text-white'
            }`}
          >
            {exporting ? (
              <>
                <div className="w-3 h-3 rounded-full border border-surface-500 border-t-transparent animate-spin" />
                Exporting...
              </>
            ) : exported ? (
              <>
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                Saved
              </>
            ) : (
              <>
                <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Export Report
              </>
            )}
          </button>
          </div>
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

      {/* Bottom row: Donut + System Risk Gauge */}
      <div className={`grid grid-cols-2 gap-4 ${a('animate-fadeIn')}`} style={animate ? { animationDelay: '500ms' } : undefined}>
        <SeverityDonut />
        <SystemRiskGauge />
      </div>
    </div>
  )
}

// ─── System Risk Gauge ──────────────────────────────────────
function SystemRiskGauge() {
  const result = useAnalysisStore(s => s.result)
  if (!result) return null

  const totalRisk = Math.round((result.simulation.totalRiskBefore ?? 0) * 100)
  const riskGrade = totalRisk > 80 ? 'F' : totalRisk > 60 ? 'D' : totalRisk > 40 ? 'C' : totalRisk > 20 ? 'B' : 'A'

  const rc = result.simulation.riskConfidence
  const ciLow = rc ? Math.round(rc.lowerBefore * 100) : totalRisk
  const ciHigh = rc ? Math.round(rc.upperBefore * 100) : totalRisk

  // Gauge geometry
  const size = 160
  const strokeWidth = 14
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  // Start from bottom-left (~135°) and sweep 270°
  const startAngle = 135
  const sweepAngle = 270
  const progress = Math.min(totalRisk, 100) / 100
  const dashLen = circumference * (sweepAngle / 360)
  const filledDash = dashLen * progress
  const gapDash = dashLen - filledDash

  const gradeColor = totalRisk > 70 ? '#D76B5A' : totalRisk > 40 ? '#E0953F' : '#82a968'

  return (
    <div className="glass-card rounded-card p-5 flex flex-col items-center justify-center card-hover">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="mb-3">
        {/* Background track */}
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke="currentColor"
          className="text-surface-300"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={`${dashLen} ${circumference - dashLen}`}
          strokeDashoffset={-circumference * (startAngle / 360)}
          transform={`rotate(0, ${size / 2}, ${size / 2})`}
        />
        {/* Filled arc */}
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none"
          stroke={gradeColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={`${filledDash} ${circumference - filledDash}`}
          strokeDashoffset={-circumference * (startAngle / 360)}
          transform={`rotate(0, ${size / 2}, ${size / 2})`}
          style={{ transition: 'stroke-dasharray 0.8s ease-out' }}
        />
        {/* Center text */}
        <text x={size / 2} y={size / 2 - 4} textAnchor="middle" dominantBaseline="central"
          fill="currentColor" className="text-surface-100" fontSize="32" fontWeight="900" fontFamily="Inter, sans-serif">
          {totalRisk}%
        </text>
        <text x={size / 2} y={size / 2 + 22} textAnchor="middle" dominantBaseline="central"
          fill={gradeColor} fontSize="14" fontWeight="700" fontFamily="Inter, sans-serif">
          {riskGrade}
        </text>
      </svg>
      <div className="text-[11px] font-bold text-surface-300 uppercase tracking-widest mb-1">System Risk</div>
      <div className="text-[10px] text-surface-500 font-mono">{ciLow}–{ciHigh}% CI</div>
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

// ─── Fix-All Panel ────────────────────────────────────────────
function FixAllPanel({
  phase, vulns, agents, canUndo, undoing, rescanning, onUndo, onRescan, onDismiss
}: {
  phase: FixPhase
  vulns: FixVulnRow[]
  agents: ReturnType<typeof useAgentStore.getState>['agents']
  canUndo: boolean
  undoing: boolean
  rescanning: boolean
  onUndo: () => void
  onRescan: () => void
  onDismiss: () => void
}) {
  const total = vulns.length
  const done = vulns.filter(v => v.status === 'done').length
  const failed = vulns.filter(v => v.status === 'failed').length
  const running = vulns.find(v => v.status === 'running')

  return (
    <div className="bg-surface-900 border border-green-500/30 rounded-card p-5 mb-6 animate-slideUp">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-2 h-2 rounded-full ${phase === 'patching' ? 'bg-green-400 animate-pulse' : 'bg-green-500'}`} />
          <div>
            <div className="text-sm font-bold text-white">
              {phase === 'patching' ? 'Agents Patching Vulnerabilities' : 'Patching Complete'}
            </div>
            <div className="text-[10px] text-surface-400 mt-0.5">
              {phase === 'patching'
                ? `${done}/${total} done · ${failed} failed${running ? ` · currently fixing ${running.affectedPackage}` : ''}`
                : `${done} succeeded, ${failed} failed out of ${total}`}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {phase === 'done' && (
            <>
              <button
                onClick={onRescan}
                disabled={rescanning}
                className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-btn bg-green-500/20 border border-green-500/50 text-green-200 hover:bg-green-500/30 transition-all btn-hover disabled:opacity-40"
              >
                {rescanning ? 'Rescanning...' : 'Rescan Codebase'}
              </button>
              {canUndo && (
                <button
                  onClick={onUndo}
                  disabled={undoing}
                  className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-btn bg-surface-800 border border-surface-700 text-surface-300 hover:bg-surface-700 hover:text-white transition-all btn-hover disabled:opacity-40"
                >
                  {undoing ? 'Undoing...' : 'Undo All Changes'}
                </button>
              )}
              <button
                onClick={onDismiss}
                className="text-surface-500 hover:text-white transition-colors px-2"
                title="Dismiss"
              >
                ✕
              </button>
            </>
          )}
        </div>
      </div>

      {/* Progress bar */}
      {phase === 'patching' && total > 0 && (
        <div className="h-1 bg-surface-800 rounded-full overflow-hidden mb-4">
          <div
            className="h-full bg-green-400 transition-all duration-300"
            style={{ width: `${((done + failed) / total) * 100}%` }}
          />
        </div>
      )}

      {/* Vuln rows with agent cards */}
      <div className="grid gap-2 max-h-[420px] overflow-y-auto pr-1">
        {vulns.map((v) => {
          const agent = v.agentId ? agents[v.agentId] : undefined
          const lastLines = agent?.outputLines.slice(-3) ?? []
          const statusColor =
            v.status === 'done' ? 'text-green-400 border-green-500/40 bg-green-500/5' :
            v.status === 'failed' ? 'text-red-400 border-red-500/40 bg-red-500/5' :
            v.status === 'running' ? 'text-blue-300 border-blue-500/50 bg-blue-500/5' :
            'text-surface-500 border-surface-800 bg-surface-900'

          return (
            <div key={`${v.index}-${v.cveId}`} className={`border rounded-btn p-3 transition-all ${statusColor}`}>
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-[10px] font-black font-mono shrink-0">#{v.index + 1}</span>
                  <span className="text-xs font-bold text-white truncate">{v.affectedPackage}</span>
                  <span className="text-[10px] text-surface-500 font-mono truncate">→ {v.patchedVersion || 'latest'}</span>
                  <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded-full border ${SEVERITY_COLORS[v.severity] ?? ''}`}>
                    {v.severity}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {v.taskType && (
                    <span className={`text-[8px] uppercase font-black tracking-wider px-1.5 py-0.5 rounded-full border ${
                      v.taskType === 'critical-exploit' ? 'text-red-300 border-red-500/50 bg-red-500/10' :
                      v.taskType === 'security-refactor' ? 'text-orange-300 border-orange-500/50 bg-orange-500/10' :
                      v.taskType === 'breaking-upgrade' ? 'text-purple-300 border-purple-500/50 bg-purple-500/10' :
                      v.taskType === 'deep-analysis' ? 'text-cyan-300 border-cyan-500/50 bg-cyan-500/10' :
                      v.taskType === 'multi-service-patch' ? 'text-pink-300 border-pink-500/50 bg-pink-500/10' :
                      v.taskType === 'compliance-patch' ? 'text-yellow-300 border-yellow-500/50 bg-yellow-500/10' :
                      v.taskType === 'config-hardening' ? 'text-teal-300 border-teal-500/50 bg-teal-500/10' :
                      'text-surface-400 border-surface-600 bg-surface-800'
                    }`}>
                      {v.taskType.replace(/-/g, ' ')}
                    </span>
                  )}
                  <span className="text-[9px] font-bold text-indigo-300" title={v.reasoning || v.model}>
                    {v.displayName || v.model.split('/').pop()}
                  </span>
                  {v.provider && (
                    <span className="text-[8px] text-surface-600">{v.provider}</span>
                  )}
                  {v.status === 'running' && (
                    <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                  )}
                  {v.status === 'done' && (
                    <svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                  )}
                  {v.status === 'failed' && (
                    <svg className="w-3 h-3 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  )}
                  {v.status === 'pending' && (
                    <span className="text-[9px] text-surface-600 uppercase">queued</span>
                  )}
                </div>
              </div>
              <div className="text-[10px] text-surface-500 font-mono truncate mb-1">{v.cveId} — {v.title}</div>
              {v.reasoning && v.status === 'running' && (
                <div className="text-[9px] text-surface-500 italic truncate mb-1">{v.reasoning}</div>
              )}

              {/* Live output lines from the agent */}
              {lastLines.length > 0 && v.status === 'running' && (
                <div className="bg-black/40 rounded px-2 py-1.5 mt-1.5 font-mono text-[9px] text-surface-400 space-y-0.5">
                  {lastLines.map((line, idx) => (
                    <div key={idx} className="truncate">{line}</div>
                  ))}
                </div>
              )}

              {/* Changed files summary on success */}
              {v.status === 'done' && v.changedFiles.length > 0 && (
                <div className="text-[9px] text-green-400/80 mt-1 font-mono truncate">
                  Patched: {v.changedFiles.join(', ')}
                </div>
              )}

              {/* Error on failure */}
              {v.status === 'failed' && v.error && (
                <div className="text-[9px] text-red-400/80 mt-1 truncate">{v.error}</div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

