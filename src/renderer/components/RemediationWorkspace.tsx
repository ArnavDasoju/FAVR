import { useState, useEffect, useRef } from 'react'
import { useWorkspaceStore, type ActiveAgent, type CompletedVuln } from '../stores/workspaceStore'
import { useAnalysisStore } from '../stores/analysisStore'
import type { FavrAgentAssignment } from '../../shared/types'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/30',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
}

interface RemediationWorkspaceProps {
  codebasePath: string
  onBack: () => void
}

export default function RemediationWorkspace({ codebasePath, onBack }: RemediationWorkspaceProps) {
  const store = useWorkspaceStore()
  const result = useAnalysisStore(s => s.result)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [launching, setLaunching] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [undoing, setUndoing] = useState(false)

  // IPC event listeners
  useEffect(() => {
    const unsubs: (() => void)[] = []

    unsubs.push(window.api.on('workspace:started', (data: unknown) => {
      const d = data as { sessionId: string }
      store.startSession(d.sessionId)
    }))

    unsubs.push(window.api.on('workspace:agentSpawned', (data: unknown) => {
      store.agentSpawned(data as { agentId: string; vulnId: string; cveId: string; model: string; estimatedCost: number })
    }))

    unsubs.push(window.api.on('agent:output', (data: unknown) => {
      const d = data as { agentId: string; line: string }
      store.agentProgress(d.agentId, 0, d.line)
    }))

    unsubs.push(window.api.on('agent:status', (data: unknown) => {
      const d = data as { agentId: string; progress: number }
      const agents = useWorkspaceStore.getState().activeAgents
      if (agents[d.agentId]) {
        store.agentProgress(d.agentId, d.progress, '')
      }
    }))

    unsubs.push(window.api.on('workspace:agentDone', (data: unknown) => {
      store.agentDone(data as { agentId: string; vulnId: string; cveId: string; success: boolean; actualCost: number; changedFiles: string[]; durationMs: number; error?: string })
    }))

    unsubs.push(window.api.on('workspace:agentSkipped', (data: unknown) => {
      const d = data as { vulnId: string }
      store.agentSkipped(d.vulnId)
    }))

    unsubs.push(window.api.on('workspace:budgetUpdate', (data: unknown) => {
      const d = data as { spent: number; remaining: number }
      store.budgetUpdate(d.spent, d.remaining)
    }))

    unsubs.push(window.api.on('workspace:complete', () => {
      store.sessionComplete({ succeeded: 0, failed: 0, skipped: 0, totalSpent: 0 })
    }))

    unsubs.push(window.api.on('workspace:paused', () => store.sessionPaused()))
    unsubs.push(window.api.on('workspace:resumed', () => store.sessionResumed()))
    unsubs.push(window.api.on('workspace:cancelled', () => store.sessionCancelled()))

    return () => unsubs.forEach(fn => fn())
  }, [])

  // Load preview on mount
  useEffect(() => {
    if (store.status === 'configuring' && store.assignments.length === 0) {
      loadPreview()
    }
  }, [store.status])

  async function loadPreview() {
    setPreviewLoading(true)
    setError(null)
    try {
      const r = await window.api.invoke('optimizer:preview', {
        budget: store.budgetInput,
        maxConcurrent: store.maxConcurrent,
        preferFree: store.preferFree,
      }) as { assignments: FavrAgentAssignment[]; expectedFixRate: number; savingsVsNaive: number; skippedVulns: { vulnId: string }[] }
      store.setAssignments(r.assignments, {
        expectedFixRate: r.expectedFixRate,
        savingsVsNaive: r.savingsVsNaive,
        skippedVulns: r.skippedVulns.map(s => s.vulnId),
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
    setPreviewLoading(false)
  }

  async function handleLaunch() {
    setLaunching(true)
    setError(null)
    try {
      await window.api.invoke('workspace:start', {
        codebasePath,
        budget: store.budgetInput,
        maxConcurrent: store.maxConcurrent,
        preferFree: store.preferFree,
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setLaunching(false)
    }
  }

  async function handlePause() {
    await window.api.invoke('workspace:pause')
  }

  async function handleResume() {
    await window.api.invoke('workspace:resume')
  }

  async function handleCancel() {
    await window.api.invoke('workspace:cancel')
  }

  async function handleUndo() {
    setUndoing(true)
    try {
      await window.api.invoke('fix:undo')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
    setUndoing(false)
  }

  function handleDone() {
    store.reset()
    onBack()
  }

  const isActive = store.status === 'running' || store.status === 'paused'
  const isDone = store.status === 'complete' || store.status === 'cancelled'

  return (
    <div className="h-full overflow-y-auto p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <button
            onClick={isDone ? handleDone : onBack}
            disabled={isActive}
            className="text-surface-400 hover:text-white transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <div>
            <h1 className="text-lg font-black text-white">Remediation Workspace</h1>
            <p className="text-[11px] text-surface-400 mt-0.5 font-mono">{codebasePath}</p>
          </div>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          {isActive && (
            <>
              {store.status === 'running' ? (
                <button onClick={handlePause} className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-btn bg-amber-500/10 border border-amber-500/40 text-amber-300 hover:bg-amber-500/20 transition-all btn-hover">
                  <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16" /><rect x="14" y="4" width="4" height="16" /></svg>
                  Pause
                </button>
              ) : (
                <button onClick={handleResume} className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-btn bg-green-500/10 border border-green-500/40 text-green-300 hover:bg-green-500/20 transition-all btn-hover">
                  <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 24 24"><polygon points="5,3 19,12 5,21" /></svg>
                  Resume
                </button>
              )}
              <button onClick={handleCancel} className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-btn bg-red-500/10 border border-red-500/30 text-red-300 hover:bg-red-500/20 transition-all btn-hover">
                Cancel
              </button>
            </>
          )}
          {isDone && (
            <>
              <button onClick={handleUndo} disabled={undoing} className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-btn bg-surface-800 border border-surface-700 text-surface-300 hover:bg-surface-700 hover:text-white transition-all btn-hover disabled:opacity-40">
                {undoing ? 'Undoing...' : 'Undo All Changes'}
              </button>
              <button onClick={handleDone} className="flex items-center gap-1.5 text-[10px] font-black uppercase tracking-wider px-3 py-1.5 rounded-btn bg-green-500/10 border border-green-500/40 text-green-300 hover:bg-green-500/20 transition-all btn-hover">
                Done
              </button>
            </>
          )}
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 bg-red-500/10 border border-red-500/30 rounded-btn text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Config panel — pre-launch */}
      {store.status === 'configuring' && (
        <ConfigPanel
          loading={previewLoading}
          launching={launching}
          assignments={store.assignments}
          skippedVulns={store.skippedVulns}
          budgetInput={store.budgetInput}
          maxConcurrent={store.maxConcurrent}
          preferFree={store.preferFree}
          expectedFixRate={store.expectedFixRate}
          savingsVsNaive={store.savingsVsNaive}
          onConfigChange={(c) => { store.setConfig(c); }}
          onRefresh={loadPreview}
          onLaunch={handleLaunch}
        />
      )}

      {/* Active workspace */}
      {(isActive || isDone) && (
        <>
          {/* Budget bar */}
          <BudgetBar budget={store.budgetInput} spent={store.spent} />

          {/* Summary stats */}
          <SummaryBar
            total={store.assignments.length}
            completed={store.completed.length}
            succeeded={store.completed.filter(c => c.success).length}
            failed={store.completed.filter(c => !c.success).length}
            skipped={store.skippedVulns.length}
            activeCount={Object.keys(store.activeAgents).length}
            elapsed={store.startedAt ? Date.now() - store.startedAt : 0}
            status={store.status}
          />

          {/* Active agent cards grid */}
          {Object.keys(store.activeAgents).length > 0 && (
            <div className="mb-5">
              <h3 className="text-[10px] font-black uppercase tracking-wider text-surface-400 mb-3">Active Agents</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.values(store.activeAgents).map(agent => (
                  <WorkspaceAgentCard key={agent.agentId} agent={agent} />
                ))}
              </div>
            </div>
          )}

          {/* Patch queue / results */}
          <PatchQueue
            assignments={store.assignments}
            activeAgents={store.activeAgents}
            completed={store.completed}
            skippedVulns={store.skippedVulns}
          />
        </>
      )}
    </div>
  )
}

// ─── Config Panel ────────────────────────────────────────────

function ConfigPanel({ loading, launching, assignments, skippedVulns, budgetInput, maxConcurrent, preferFree, expectedFixRate, savingsVsNaive, onConfigChange, onRefresh, onLaunch }: {
  loading: boolean
  launching: boolean
  assignments: FavrAgentAssignment[]
  skippedVulns: string[]
  budgetInput: number
  maxConcurrent: number
  preferFree: boolean
  expectedFixRate: number
  savingsVsNaive: number
  onConfigChange: (c: { budgetInput?: number; maxConcurrent?: number; preferFree?: boolean }) => void
  onRefresh: () => void
  onLaunch: () => void
}) {
  const totalEstCost = assignments.reduce((s, a) => s + a.estimatedCost, 0)

  return (
    <div className="space-y-5">
      {/* Config controls */}
      <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
        <h3 className="text-sm font-bold text-white mb-4">Workspace Configuration</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Budget */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-surface-400 mb-2 block">
              Budget: ${budgetInput.toFixed(2)}
            </label>
            <input
              type="range"
              min={0}
              max={50}
              step={0.5}
              value={budgetInput}
              onChange={e => onConfigChange({ budgetInput: parseFloat(e.target.value) })}
              className="w-full accent-sage-500"
            />
            <div className="flex justify-between text-[9px] text-surface-500 mt-1">
              <span>$0 (free only)</span>
              <span>$50</span>
            </div>
          </div>

          {/* Concurrent agents */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-surface-400 mb-2 block">
              Concurrent Agents: {maxConcurrent}
            </label>
            <input
              type="range"
              min={1}
              max={5}
              step={1}
              value={maxConcurrent}
              onChange={e => onConfigChange({ maxConcurrent: parseInt(e.target.value) })}
              className="w-full accent-sage-500"
            />
            <div className="flex justify-between text-[9px] text-surface-500 mt-1">
              <span>1</span>
              <span>5</span>
            </div>
          </div>

          {/* Prefer free */}
          <div>
            <label className="text-[10px] font-bold uppercase tracking-wider text-surface-400 mb-2 block">
              Prefer Free Models
            </label>
            <button
              onClick={() => onConfigChange({ preferFree: !preferFree })}
              className={`w-full py-2.5 rounded-btn text-xs font-bold border transition-all ${
                preferFree
                  ? 'bg-sage-500/15 border-sage-500/40 text-sage-300'
                  : 'bg-surface-800 border-surface-700 text-surface-400'
              }`}
            >
              {preferFree ? 'On — Use free when viable' : 'Off — Best model per task'}
            </button>
          </div>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider px-3 py-1.5 rounded-btn bg-surface-800 border border-surface-700 text-surface-300 hover:bg-surface-700 hover:text-white transition-all btn-hover disabled:opacity-40"
          >
            {loading ? (
              <><div className="w-3 h-3 rounded-full border border-surface-500 border-t-transparent animate-spin" /> Optimizing...</>
            ) : 'Refresh Preview'}
          </button>
        </div>
      </div>

      {/* Preview table */}
      {assignments.length > 0 && (
        <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-white">Agent Assignment Preview</h3>
            <div className="flex items-center gap-4 text-[10px] text-surface-400">
              <span>Est. cost: <span className="text-white font-bold">${totalEstCost.toFixed(4)}</span></span>
              <span>Fix rate: <span className="text-sage-300 font-bold">{(expectedFixRate * 100).toFixed(0)}%</span></span>
              {savingsVsNaive > 0 && <span>Savings: <span className="text-green-300 font-bold">${savingsVsNaive.toFixed(2)}</span></span>}
              {skippedVulns.length > 0 && <span className="text-amber-400">{skippedVulns.length} skipped</span>}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="text-[9px] font-bold uppercase tracking-wider text-surface-500 border-b border-surface-800">
                  <th className="pb-2 pr-3">#</th>
                  <th className="pb-2 pr-3">CVE</th>
                  <th className="pb-2 pr-3">Severity</th>
                  <th className="pb-2 pr-3">Model</th>
                  <th className="pb-2 pr-3">Est. Cost</th>
                  <th className="pb-2">Success %</th>
                </tr>
              </thead>
              <tbody>
                {assignments.map((a, i) => (
                  <tr key={a.vulnId} className="border-b border-surface-800/50 hover:bg-surface-800/30 transition-colors">
                    <td className="py-2 pr-3 text-[10px] font-mono text-surface-500">{i + 1}</td>
                    <td className="py-2 pr-3 text-xs font-bold text-white font-mono">{a.cveId}</td>
                    <td className="py-2 pr-3">
                      <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded-full border ${SEVERITY_COLORS[a.severity] ?? ''}`}>
                        {a.severity}
                      </span>
                    </td>
                    <td className="py-2 pr-3 text-[11px] text-surface-300 font-mono">{a.assignedModel.split('/').pop()}</td>
                    <td className="py-2 pr-3 text-[11px] text-surface-300 font-mono">
                      {a.estimatedCost === 0 ? <span className="text-sage-400">free</span> : `$${a.estimatedCost.toFixed(4)}`}
                    </td>
                    <td className="py-2 text-[11px] font-bold text-surface-300">{(a.expectedSuccessRate * 100).toFixed(0)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Launch */}
          <div className="mt-5 flex items-center justify-between">
            <p className="text-[10px] text-surface-500">
              {assignments.length} vulnerabilities will be patched by {new Set(assignments.map(a => a.assignedModel)).size} model(s)
            </p>
            <button
              onClick={onLaunch}
              disabled={launching || assignments.length === 0}
              className="flex items-center gap-2 text-xs font-black uppercase tracking-wider px-5 py-2.5 rounded-btn bg-sage-500/20 border border-sage-500/50 text-sage-200 hover:bg-sage-500/30 hover:border-sage-500/70 transition-all btn-hover disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {launching ? (
                <><div className="w-3.5 h-3.5 rounded-full border-2 border-sage-400 border-t-transparent animate-spin" /> Launching...</>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                  Launch Workspace
                </>
              )}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Budget Bar ──────────────────────────────────────────────

function BudgetBar({ budget, spent }: { budget: number; spent: number }) {
  const remaining = budget - spent
  const pct = budget > 0 ? (spent / budget) * 100 : 0
  const barColor = pct > 80 ? 'bg-red-400' : pct > 50 ? 'bg-amber-400' : 'bg-sage-400'

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4 mb-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] font-bold uppercase tracking-wider text-surface-400">Budget</span>
        <div className="flex items-center gap-4 text-[10px]">
          <span className="text-surface-400">Spent: <span className="text-white font-bold">${spent.toFixed(4)}</span></span>
          <span className="text-surface-400">Remaining: <span className={`font-bold ${remaining < 0 ? 'text-red-400' : 'text-sage-300'}`}>${remaining.toFixed(4)}</span></span>
          <span className="text-surface-500">/ ${budget.toFixed(2)}</span>
        </div>
      </div>
      <div className="h-2 bg-surface-800 rounded-full overflow-hidden">
        <div className={`h-full ${barColor} rounded-full transition-all duration-500`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
    </div>
  )
}

// ─── Summary Bar ─────────────────────────────────────────────

function SummaryBar({ total, completed, succeeded, failed, skipped, activeCount, elapsed, status }: {
  total: number; completed: number; succeeded: number; failed: number; skipped: number; activeCount: number; elapsed: number; status: string
}) {
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (status !== 'running') return
    const t = setInterval(() => setTick(n => n + 1), 1000)
    return () => clearInterval(t)
  }, [status])

  const formatTime = (ms: number) => {
    const s = Math.floor(ms / 1000)
    const m = Math.floor(s / 60)
    return m > 0 ? `${m}m ${s % 60}s` : `${s}s`
  }

  return (
    <div className="grid grid-cols-5 gap-3 mb-5">
      {[
        { label: 'Active', value: activeCount, color: 'text-blue-300' },
        { label: 'Succeeded', value: succeeded, color: 'text-green-400' },
        { label: 'Failed', value: failed, color: failed > 0 ? 'text-red-400' : 'text-surface-500' },
        { label: 'Skipped', value: skipped, color: skipped > 0 ? 'text-amber-400' : 'text-surface-500' },
        { label: 'Elapsed', value: formatTime(elapsed + tick * 0), color: 'text-surface-300', isText: true },
      ].map(s => (
        <div key={s.label} className="bg-surface-900 border border-surface-800 rounded-card p-3 text-center">
          <div className={`text-lg font-black ${s.color}`}>
            {'isText' in s ? formatTime(elapsed) : s.value}
          </div>
          <div className="text-[9px] font-bold uppercase tracking-wider text-surface-500 mt-1">{s.label}</div>
        </div>
      ))}
    </div>
  )
}

// ─── Workspace Agent Card ────────────────────────────────────

function WorkspaceAgentCard({ agent }: { agent: ActiveAgent }) {
  const feedRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight
    }
  }, [agent.outputLines.length])

  return (
    <div className="bg-surface-900 border border-blue-500/30 rounded-card flex flex-col animate-slideUp">
      {/* Header */}
      <div className="px-4 pt-4 pb-3 flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <span className="text-sm font-bold text-white truncate">{agent.cveId}</span>
          <span className="text-[10px] font-mono text-surface-500 uppercase tracking-wider">
            {agent.model.split('/').pop()}
          </span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0 bg-surface-950 px-2.5 py-1 rounded">
          <div className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
          <span className="text-[10px] font-bold tracking-wider text-surface-400 uppercase">Running</span>
        </div>
      </div>

      {/* Progress bar */}
      <div className="px-4 pb-3">
        <div className="w-full h-1 bg-surface-800 rounded-full overflow-hidden">
          <div className="h-full bg-blue-400 rounded-full transition-all duration-500 animate-pulse" style={{ width: `${agent.progress}%` }} />
        </div>
      </div>

      {/* Terminal output */}
      <div ref={feedRef} className="mx-3 mb-3 rounded bg-surface-950 overflow-hidden p-3" style={{ minHeight: '100px', maxHeight: '160px', overflowY: 'auto' }}>
        {agent.outputLines.length > 0 ? (
          agent.outputLines.slice(-10).map((line, i) => (
            <div key={i} className="text-[11px] text-surface-500 truncate">{line}</div>
          ))
        ) : (
          <span className="text-surface-600 text-[10px] font-mono">Waiting for output...</span>
        )}
      </div>

      {/* Cost estimate */}
      <div className="px-4 pb-3 flex items-center justify-between">
        <span className="text-[9px] text-surface-500">Est. cost</span>
        <span className="text-[10px] font-mono text-surface-400">
          {agent.estimatedCost === 0 ? 'free' : `$${agent.estimatedCost.toFixed(4)}`}
        </span>
      </div>
    </div>
  )
}

// ─── Patch Queue ─────────────────────────────────────────────

function PatchQueue({ assignments, activeAgents, completed, skippedVulns }: {
  assignments: FavrAgentAssignment[]
  activeAgents: Record<string, ActiveAgent>
  completed: CompletedVuln[]
  skippedVulns: string[]
}) {
  const completedMap = new Map(completed.map(c => [c.vulnId, c]))
  const activeMap = new Map(Object.values(activeAgents).map(a => [a.vulnId, a]))
  const skippedSet = new Set(skippedVulns)

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
      <h3 className="text-[10px] font-black uppercase tracking-wider text-surface-400 mb-3">Patch Queue</h3>
      <div className="space-y-1.5 max-h-[400px] overflow-y-auto pr-1">
        {assignments.map((a, i) => {
          const comp = completedMap.get(a.vulnId)
          const active = activeMap.get(a.vulnId)
          const isSkipped = skippedSet.has(a.vulnId)

          let statusIcon: JSX.Element
          let statusColor: string
          let statusLabel: string

          if (comp?.success) {
            statusIcon = <svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
            statusColor = 'border-green-500/30 bg-green-500/5'
            statusLabel = 'done'
          } else if (comp && !comp.success) {
            statusIcon = <svg className="w-3 h-3 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
            statusColor = 'border-red-500/30 bg-red-500/5'
            statusLabel = 'failed'
          } else if (active) {
            statusIcon = <div className="w-2.5 h-2.5 rounded-full bg-blue-400 animate-pulse" />
            statusColor = 'border-blue-500/30 bg-blue-500/5'
            statusLabel = 'running'
          } else if (isSkipped) {
            statusIcon = <span className="text-[10px] text-amber-400">--</span>
            statusColor = 'border-amber-500/20 bg-amber-500/5 opacity-60'
            statusLabel = 'skipped'
          } else {
            statusIcon = <div className="w-2 h-2 rounded-full bg-surface-700" />
            statusColor = 'border-surface-800'
            statusLabel = 'queued'
          }

          return (
            <div key={a.vulnId} className={`flex items-center gap-3 px-3 py-2 rounded-btn border transition-all ${statusColor}`}>
              <span className="text-[10px] font-mono text-surface-500 w-5 shrink-0">{i + 1}</span>
              <div className="w-4 shrink-0 flex justify-center">{statusIcon}</div>
              <span className="text-xs font-bold text-white font-mono flex-shrink-0">{a.cveId}</span>
              <span className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded-full border shrink-0 ${SEVERITY_COLORS[a.severity] ?? ''}`}>
                {a.severity}
              </span>
              <span className="text-[10px] text-surface-500 font-mono truncate flex-1">{a.assignedModel.split('/').pop()}</span>
              <span className="text-[10px] text-surface-500 font-mono shrink-0">
                {comp ? `$${comp.cost.toFixed(4)}` : a.estimatedCost === 0 ? 'free' : `~$${a.estimatedCost.toFixed(4)}`}
              </span>
              {comp?.error && (
                <span className="text-[9px] text-red-400 truncate max-w-[200px]" title={comp.error}>{comp.error}</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
