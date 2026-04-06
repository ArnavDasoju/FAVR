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

  const isRunning = phase !== 'idle' && phase !== 'complete' && phase !== 'error'

  async function handleLoadDemo() {
    setLoading(true)
    try {
      await window.api.invoke('analysis:loadDemo')
    } catch (err) {
      console.error('Demo load failed:', err)
    }
    setLoading(false)
  }

  async function handleRunAnalysis() {
    setLoading(true)
    try {
      await window.api.invoke('analysis:run', {
        codebasePath: mode === 'remediation' && codebasePath ? codebasePath : undefined,
        iterations: 5000
      })
    } catch (err) {
      console.error('Analysis failed:', err)
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
          <h1 className="text-3xl font-black text-white mb-2">FAVR</h1>
          <p className="text-surface-400 text-sm mb-8">
            Vulnerability prioritization powered by Attack Graph analysis,
            Bayesian risk propagation, Monte Carlo simulation, and Pareto optimization.
          </p>

          {/* Mode Selector */}
          <div className="flex gap-3 mb-6">
            <button
              onClick={() => setMode('analysis')}
              className={`flex-1 p-4 rounded-card border text-left transition-colors ${
                mode === 'analysis'
                  ? 'bg-surface-800 border-white/20 text-white'
                  : 'bg-surface-900 border-surface-800 text-surface-400 hover:border-surface-700'
              }`}
            >
              <div className="text-sm font-bold mb-1">Analysis Only</div>
              <div className="text-[10px] text-surface-500">Upload docs → Prioritize → Report</div>
            </button>
            <button
              onClick={() => setMode('remediation')}
              className={`flex-1 p-4 rounded-card border text-left transition-colors ${
                mode === 'remediation'
                  ? 'bg-surface-800 border-white/20 text-white'
                  : 'bg-surface-900 border-surface-800 text-surface-400 hover:border-surface-700'
              }`}
            >
              <div className="text-sm font-bold mb-1">Full Remediation</div>
              <div className="text-[10px] text-surface-500">Analysis + Agents patch the code</div>
            </button>
          </div>

          {/* Document Upload */}
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

          {/* Codebase Path (Mode 2 only) */}
          {mode === 'remediation' && (
            <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-4">
              <div className="text-xs font-bold text-white mb-2">Codebase Directory</div>
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
          )}

          {/* Actions */}
          <div className="flex gap-3">
            <button
              onClick={handleLoadDemo}
              disabled={loading}
              className="flex-1 bg-surface-800 border border-surface-700 text-white font-bold text-sm py-3 rounded-btn hover:bg-surface-700 disabled:opacity-50 transition-colors"
            >
              Load Demo Scenario
            </button>
            <button
              onClick={handleRunAnalysis}
              disabled={loading}
              className="flex-1 bg-white text-black font-bold text-sm py-3 rounded-btn hover:bg-surface-200 disabled:opacity-50 transition-colors"
            >
              Run Analysis
            </button>
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
        <div className="max-w-md w-full p-8">
          <h2 className="text-lg font-bold text-white mb-4">Analyzing...</h2>
          <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-surface-400 uppercase">{phase}</span>
              <span className="text-xs font-mono text-surface-500">{progress}%</span>
            </div>
            <div className="w-full h-2 bg-surface-800 rounded-full overflow-hidden mb-2">
              <div
                className="h-full bg-white rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              />
            </div>
            <p className="text-[11px] text-surface-500">{message}</p>
          </div>
        </div>
      </div>
    )
  }

  // ─── Results ────────────────────────────────────────────
  const totalRisk = Math.round(result!.simulation.totalRiskBefore * 100)
  const reduction = Math.round(result!.simulation.riskReduction)
  const vulnCount = result!.graph.vulnerabilities.length
  const critCount = result!.graph.vulnerabilities.filter(v => v.severity === 'critical').length

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Hero Stats */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center">
          <div className="text-3xl font-black text-red-400">{totalRisk}%</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">System Risk</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center">
          <div className="text-3xl font-black text-green-400">-{reduction}%</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">After Remediation</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center">
          <div className="text-3xl font-black text-white">{vulnCount}</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Vulnerabilities</div>
        </div>
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4 text-center">
          <div className="text-3xl font-black text-red-400">{critCount}</div>
          <div className="text-[10px] text-surface-500 uppercase font-bold mt-1">Critical</div>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <DependencyGraph />
        <ServiceHeatmap />
      </div>

      {/* Top 5 Priority Patches */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-6">
        <h3 className="text-sm font-bold text-white mb-3">Top Priority Patches (FAVR Optimized)</h3>
        <div className="grid gap-2">
          {result!.simulation.optimalOrder.slice(0, 5).map((vulnId, i) => {
            const vuln = result!.graph.vulnerabilities.find(v => v.id === vulnId)
            if (!vuln) return null
            const ci = result!.simulation.confidenceIntervals[i]
            const sevStyle = SEVERITY_COLORS[vuln.severity]

            return (
              <div key={vulnId} className="flex items-center gap-3 bg-surface-800/50 rounded-btn p-3">
                <div className="w-7 h-7 rounded-full bg-surface-800 flex items-center justify-center text-xs font-black text-white">
                  {i + 1}
                </div>
                <div className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${sevStyle}`}>
                  {vuln.severity}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-bold text-white truncate">{vuln.cveId}</div>
                  <div className="text-[10px] text-surface-500 truncate">{vuln.title}</div>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-xs font-bold text-surface-300">{Math.round(ci.frequency * 100)}%</div>
                  <div className="text-[10px] text-surface-600">confidence</div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <SeverityDonut />
        <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
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
              <div className="text-lg font-black text-white">{result!.graph.services.length}</div>
              <div className="text-[10px] text-surface-500">Services</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
