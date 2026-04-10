import { useState } from 'react'
import { useAnalysisStore } from '../stores/analysisStore'
import DependencyGraph from './charts/DependencyGraph'
import ServiceHeatmap from './charts/ServiceHeatmap'
import SeverityDonut from './charts/SeverityDonut'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30'
}

export default function Dashboard() {
  const result = useAnalysisStore(s => s.result)
  const phase = useAnalysisStore(s => s.phase)
  const progress = useAnalysisStore(s => s.progress)
  const message = useAnalysisStore(s => s.message)
  const error = useAnalysisStore(s => s.error)
  const mode = useAnalysisStore(s => s.mode)
  const setMode = useAnalysisStore(s => s.setMode)

  const [codebasePath, setCodebasePath] = useState('')
  const [loading, setLoading] = useState(false)
  const [scanStats, setScanStats] = useState<{ servicesFound: number; packagesScanned: number; vulnerabilitiesFound: number; ecosystems: string[] } | null>(null)

  const isRunning = phase !== 'idle' && phase !== 'complete' && phase !== 'error'

  async function handleLoadDemo() {
    setLoading(true)
    setScanStats(null)
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

  // ─── No Analysis Yet ────────────────────────────────────
  if (!result && !isRunning) {
    return (
      <div className="h-full overflow-y-auto p-6">
        <div className="max-w-2xl mx-auto">
          <h1 className="text-3xl font-black text-white mb-2 animate-fadeIn">FAVR</h1>
          <p className="text-surface-400 text-sm mb-8 animate-slideUp stagger-1">
            Vulnerability prioritization powered by Attack Graph analysis,
            Bayesian risk propagation, Monte Carlo simulation, and Pareto optimization.
          </p>

          {/* Mode Selector */}
          <div className="flex gap-3 mb-6">
            <button
              onClick={() => setMode('analysis')}
              className={`flex-1 p-4 rounded-card border text-left transition-all duration-200 card-hover animate-slideUp stagger-1 ${
                mode === 'analysis'
                  ? 'bg-surface-800 border-white/20 text-white'
                  : 'bg-surface-900 border-surface-800 text-surface-400 hover:border-surface-700'
              }`}
            >
              <div className="text-sm font-bold mb-1">Scan Codebase</div>
              <div className="text-[10px] text-surface-500">Point at a project &rarr; Auto-discover vulns</div>
            </button>
            <button
              onClick={() => setMode('remediation')}
              className={`flex-1 p-4 rounded-card border text-left transition-all duration-200 card-hover animate-slideUp stagger-2 ${
                mode === 'remediation'
                  ? 'bg-surface-800 border-white/20 text-white'
                  : 'bg-surface-900 border-surface-800 text-surface-400 hover:border-surface-700'
              }`}
            >
              <div className="text-sm font-bold mb-1">Upload Documents</div>
              <div className="text-[10px] text-surface-500">CVE feeds, advisories &rarr; Prioritize &rarr; Report</div>
            </button>
          </div>

          {/* Scan Codebase (primary flow) */}
          {mode === 'analysis' && (
            <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-4">
              <div className="text-xs font-bold text-white mb-2">Project Directory</div>
              <p className="text-[10px] text-surface-500 mb-3">
                Select a codebase to auto-discover services, dependencies, and vulnerabilities.
                Supports Node.js, Python, Go, Rust, Java, and Ruby.
              </p>
              <div className="flex gap-2">
                <input
                  value={codebasePath}
                  onChange={(e) => setCodebasePath(e.target.value)}
                  placeholder="Path to your project..."
                  className="flex-1 bg-surface-800 border border-surface-700 rounded-btn px-3 py-2 text-xs text-white placeholder:text-surface-600 focus:outline-none focus:border-surface-500"
                />
                <button
                  onClick={handleBrowseCodebase}
                  className="bg-surface-800 border border-surface-700 rounded-btn px-3 py-2 text-xs text-surface-300 hover:bg-surface-700"
                >
                  Browse
                </button>
              </div>
              {codebasePath && (
                <div className="mt-2 text-[10px] text-surface-500 font-mono truncate">{codebasePath}</div>
              )}
            </div>
          )}

          {/* Document Upload (secondary flow) */}
          {mode === 'remediation' && (
            <>
              <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-4">
                <div className="text-xs font-bold text-white mb-2">Upload Documents</div>
                <p className="text-[10px] text-surface-500 mb-3">CVE feeds, vendor advisories, dependency maps (JSON, TXT, MD)</p>
                <button
                  onClick={handleUploadDocs}
                  className="w-full border-2 border-dashed border-surface-700 rounded-btn p-6 text-surface-500 text-xs hover:border-surface-500 hover:text-surface-300 transition-colors"
                >
                  Click to upload documents
                </button>
                {useAnalysisStore.getState().uploadedFiles.length > 0 && (
                  <div className="mt-2 text-[10px] text-green-400">
                    {useAnalysisStore.getState().uploadedFiles.length} file(s) uploaded
                  </div>
                )}
              </div>
              <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-4">
                <div className="text-xs font-bold text-white mb-2">Codebase Directory (optional)</div>
                <div className="flex gap-2">
                  <input
                    value={codebasePath}
                    onChange={(e) => setCodebasePath(e.target.value)}
                    placeholder="Path to your project..."
                    className="flex-1 bg-surface-800 border border-surface-700 rounded-btn px-3 py-2 text-xs text-white placeholder:text-surface-600 focus:outline-none focus:border-surface-500"
                  />
                  <button
                    onClick={handleBrowseCodebase}
                    className="bg-surface-800 border border-surface-700 rounded-btn px-3 py-2 text-xs text-surface-300 hover:bg-surface-700"
                  >
                    Browse
                  </button>
                </div>
              </div>
            </>
          )}

          {/* Actions */}
          <div className="flex gap-3 animate-slideUp stagger-4">
            {mode === 'analysis' ? (
              <>
                <button
                  onClick={handleLoadDemo}
                  disabled={loading}
                  className="bg-surface-800 border border-surface-700 text-surface-300 font-bold text-sm py-3 px-6 rounded-btn hover:bg-surface-700 disabled:opacity-50 transition-all btn-hover"
                >
                  Demo
                </button>
                <button
                  onClick={handleScanCodebase}
                  disabled={loading || !codebasePath}
                  className="flex-1 bg-white text-black font-bold text-sm py-3 rounded-btn hover:bg-surface-200 disabled:opacity-50 transition-all btn-hover"
                >
                  Scan Codebase
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={handleLoadDemo}
                  disabled={loading}
                  className="bg-surface-800 border border-surface-700 text-surface-300 font-bold text-sm py-3 px-6 rounded-btn hover:bg-surface-700 disabled:opacity-50 transition-all btn-hover"
                >
                  Demo
                </button>
                <button
                  onClick={handleRunAnalysis}
                  disabled={loading}
                  className="flex-1 bg-white text-black font-bold text-sm py-3 rounded-btn hover:bg-surface-200 disabled:opacity-50 transition-all btn-hover"
                >
                  Run Analysis
                </button>
              </>
            )}
          </div>

          {error && (
            <div className="mt-4 bg-red-500/10 border border-red-500/30 rounded-btn p-3 text-xs text-red-400">
              {error}
            </div>
          )}
        </div>
      </div>
    )
  }

  // ─── Running ────────────────────────────────────────────
  if (isRunning) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="max-w-md w-full p-8 animate-scaleIn">
          <h2 className="text-lg font-bold text-white mb-4">Analyzing...</h2>
          <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-bold text-surface-400 uppercase tracking-wider">{phase}</span>
              <span className="text-xs font-mono text-white">{progress}%</span>
            </div>
            <div className="w-full h-2.5 bg-surface-800 rounded-full overflow-hidden mb-3">
              <div
                className="h-full bg-white rounded-full transition-all duration-500 ease-out"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="text-[11px] text-surface-500 animate-fadeIn" key={message}>{message}</p>
          </div>
        </div>
      </div>
    )
  }

  // ─── Results ────────────────────────────────────────────
  const totalRisk = Math.round((result!.simulation.totalRiskBefore ?? 0) * 100)
  const reduction = Math.round(result!.simulation.riskReduction ?? 0)
  const vulnCount = result!.graph.vulnerabilities.length
  const critCount = result!.graph.vulnerabilities.filter(v => v.severity === 'critical').length
  const complianceRisk = result!.complianceSummary ? Math.round(result!.complianceSummary.overallComplianceRisk * 100) : 0
  const urgentCompliance = result!.complianceSummary?.violations.reduce((s, v) => s + v.urgentCount, 0) ?? 0
  const maxScheduleWeek = result!.schedule?.length > 0 ? Math.max(...result!.schedule.map(s => s.weekNumber)) : 0

  async function handleExport() {
    try {
      await window.api.invoke('analysis:exportReport')
    } catch (err) {
      console.error('Export failed:', err)
    }
  }

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Hero Stats */}
      <div className="grid grid-cols-6 gap-3 mb-6">
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-1">
          <div className="text-3xl font-black text-red-400 animate-numberGlow">{totalRisk}%</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">System Risk</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-2">
          <div className="text-3xl font-black text-green-400">-{reduction}%</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">After Remediation</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-3">
          <div className="text-3xl font-black text-white">{vulnCount}</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Vulnerabilities</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-4">
          <div className={`text-3xl font-black text-red-400 ${critCount > 0 ? 'animate-numberGlow' : ''}`}>{critCount}</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Critical</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-5">
          <div className={`text-3xl font-black ${complianceRisk > 50 ? 'text-purple-400 animate-numberGlow' : 'text-surface-400'}`}>{complianceRisk}%</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Compliance Risk</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center card-hover animate-slideUp stagger-6">
          <div className="text-3xl font-black text-blue-400">{maxScheduleWeek}wk</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Schedule</div>
        </div>
      </div>

      {/* Compliance Alerts */}
      {urgentCompliance > 0 && (
        <div className="bg-purple-500/10 border border-purple-500/30 rounded-card p-4 mb-6 flex items-center justify-between animate-slideUp stagger-7 animate-pulseGlow">
          <div className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full bg-purple-400 status-blink" />
            <div>
              <div className="text-sm font-bold text-purple-300">{urgentCompliance} Compliance Deadline{urgentCompliance !== 1 ? 's' : ''} Within 14 Days</div>
              <div className="text-[10px] text-purple-400/70 mt-0.5">
                {result!.complianceSummary?.violations.filter(v => v.urgentCount > 0).map(v => v.framework).join(', ')}
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
        <div className="animate-slideUp stagger-7"><DependencyGraph /></div>
        <div className="animate-slideUp stagger-8"><ServiceHeatmap /></div>
      </div>

      {/* Top 5 Priority Patches */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-6 animate-fadeIn" style={{ animationDelay: '400ms' }}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-bold text-white">Top Priority Patches (FAVR Optimized)</h3>
          <button
            onClick={handleExport}
            className="text-[10px] font-bold text-surface-400 hover:text-white transition-colors uppercase tracking-wider"
          >
            Export Full Report
          </button>
        </div>
        <div className="grid gap-2">
          {result!.simulation.optimalOrder.slice(0, 5).map((vulnId, i) => {
            const vuln = result!.graph.vulnerabilities.find(v => v.id === vulnId)
            if (!vuln) return null
            const ci = result!.simulation.confidenceIntervals[i]
            const sevStyle = SEVERITY_COLORS[vuln.severity]
            const blast = result!.blastRadii?.[vulnId]
            const epssDiv = Math.abs(vuln.epssScore - vuln.cvssScore / 10)
            const epssHigher = vuln.epssScore > vuln.cvssScore / 10

            return (
              <div key={vulnId} className="flex items-center gap-3 bg-surface-800/50 rounded-btn p-3 transition-all duration-150 hover:bg-surface-800 hover:translate-x-0.5">
                <div className="w-7 h-7 rounded-full bg-surface-800 flex items-center justify-center text-xs font-black text-white">
                  {i + 1}
                </div>
                <div className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${sevStyle}`}>
                  {vuln.severity}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-bold text-white truncate">{vuln.cveId}</span>
                    <span className="text-[10px] text-surface-500 font-mono">CVSS {vuln.cvssScore.toFixed(1)}</span>
                    {epssDiv > 0.15 && (
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${epssHigher ? 'bg-red-500/15 text-red-400' : 'bg-green-500/15 text-green-400'}`}>
                        EPSS {(vuln.epssScore * 100).toFixed(0)}%{epssHigher ? ' !' : ''}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-surface-500 truncate">{vuln.title}</span>
                  </div>
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

      <div className="grid grid-cols-2 gap-4 animate-fadeIn" style={{ animationDelay: '500ms' }}>
        <SeverityDonut />
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 card-hover">
          <h3 className="text-sm font-bold text-white mb-1">Engine Stats</h3>
          <div className="grid grid-cols-2 gap-3 mt-3">
            <div>
              <div className="text-lg font-black text-white">{result!.simulation.iterations.toLocaleString()}</div>
              <div className="text-[10px] text-surface-500">Simulations</div>
            </div>
            <div>
              <div className="text-lg font-black text-white">{Math.round(result!.simulation.convergenceScore * 100)}%</div>
              <div className="text-[10px] text-surface-500">Convergence</div>
            </div>
            <div>
              <div className="text-lg font-black text-white">{result!.pareto.frontierIds.length}</div>
              <div className="text-[10px] text-surface-500">Pareto Solutions</div>
            </div>
            <div>
              <div className="text-lg font-black text-white">{result!.complianceSummary?.frameworks.length ?? 0}</div>
              <div className="text-[10px] text-surface-500">Frameworks</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
