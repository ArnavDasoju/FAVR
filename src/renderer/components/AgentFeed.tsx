/**
 * AgentFeed — Fullscreen expanded view of an agent.
 *
 * Shows:
 * - Large live feed / interactive webview
 * - Real-time scrolling log output
 * - Confidence meter
 * - Current subtask description
 * - Retry history
 * - Code diff
 * - Approve/Reject buttons
 */

import { useState, useRef, useEffect } from 'react'
import { useAgentStore } from '../stores/agentStore'
import { useTaskStore } from '../stores/taskStore'
import DiffViewer from './DiffViewer'
import type { Agent, FeedMode, PipelineStep } from '@shared/types'

interface AgentFeedProps {
  agentId: string
  onClose: () => void
}

export default function AgentFeed({ agentId, onClose }: AgentFeedProps) {
  const agent = useAgentStore((s) => s.agents[agentId])
  const tasks = useTaskStore((s) => s.tasks)
  const [activeTab, setActiveTab] = useState<'pipeline' | 'logs' | 'diff'>('pipeline')
  const [feedback, setFeedback] = useState('')
  const logEndRef = useRef<HTMLDivElement>(null)

  // Find the task/subtask this agent is working on
  const relatedTask = tasks.find((t) =>
    t.subtasks?.some((s) => s.agentId === agentId)
  )
  const relatedSubtask = relatedTask?.subtasks?.find((s) => s.agentId === agentId)

  // Auto-scroll logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [agent?.outputLines.length])

  // Keyboard shortcut: ESC to close
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [onClose])

  if (!agent) {
    return (
      <div className="h-full flex items-center justify-center">
        <span className="text-surface-500">Agent not found</span>
      </div>
    )
  }

  const confidence = relatedSubtask?.confidence ?? null
  const retryCount = relatedSubtask?.retryCount ?? 0
  const needsReview = relatedSubtask?.status === 'needs_review'

  const handleApprove = () => {
    if (relatedTask) {
      window.api.invoke('task:approve', relatedTask.id)
    }
  }

  const handleReject = () => {
    if (relatedTask) {
      window.api.invoke('task:reject', relatedTask.id)
    }
  }

  const handleRetryWithFeedback = () => {
    if (relatedTask && feedback.trim()) {
      // For now, reject and resubmit with feedback
      window.api.invoke('task:reject', relatedTask.id)
      window.api.invoke('task:submit', {
        prompt: `${relatedTask.prompt}\n\nAdditional context: ${feedback}`,
        projectId: relatedTask.projectId,
        model: relatedTask.model
      })
      setFeedback('')
    }
  }

  return (
    <div className="h-full flex flex-col bg-surface-950">
      {/* Header bar */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-surface-800/50">
        <div className="flex items-center gap-4">
          <button
            onClick={onClose}
            className="text-surface-500 hover:text-white transition-colors text-sm"
          >
            &larr; Back
          </button>
          <div className="flex items-center gap-3">
            <span className="text-base font-bold text-white">{agent.name}</span>
            <span className="text-[10px] font-mono text-surface-500 uppercase">
              {agent.model.split('/').pop()}
            </span>
            <StatusBadge status={agent.status} />
          </div>
        </div>

        <div className="flex items-center gap-4">
          {/* Confidence meter */}
          {confidence !== null && (
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
                Confidence
              </span>
              <ConfidenceMeter value={confidence} />
              <span className="text-sm font-bold text-white">{confidence}%</span>
            </div>
          )}

          {retryCount > 0 && (
            <span className="text-[10px] font-mono text-surface-500">
              Retry {retryCount}
            </span>
          )}
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex gap-0 px-6 border-b border-surface-800/50">
        {(['pipeline', 'logs', 'diff'] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors ${
              activeTab === tab
                ? 'text-white border-white'
                : 'text-surface-500 border-transparent hover:text-surface-300'
            }`}
          >
            {tab === 'pipeline' ? 'Pipeline' : tab === 'logs' ? 'Logs' : 'Diff'}
          </button>
        ))}
      </div>

      {/* Content area */}
      <div className="flex-1 overflow-hidden flex flex-col">
        {activeTab === 'pipeline' && (
          <div className="flex-1 p-6 flex flex-col gap-4 overflow-y-auto">
            {/* Current task */}
            {relatedSubtask && (
              <div className="bg-surface-900 border border-surface-800 rounded-card p-4">
                <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider block mb-2">
                  Task
                </span>
                <p className="text-sm text-white">{relatedSubtask.prompt}</p>
              </div>
            )}

            {/* Pipeline timeline */}
            <div className="bg-surface-900 border border-surface-800 rounded-card p-5">
              <span className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em] block mb-4">
                Pipeline
              </span>
              <PipelineTimeline events={agent.pipeline || []} />
            </div>

            {/* Terminal output preview */}
            <div className="bg-surface-900 border border-surface-800 rounded-card overflow-hidden flex-1 min-h-[200px]">
              <div className="flex items-center gap-2 px-4 py-2 border-b border-surface-800/50">
                <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider">
                  Agent Output
                </span>
                <span className="text-[10px] text-surface-600">
                  {agent.outputLines.length} lines
                </span>
              </div>
              <div className="terminal-output text-surface-400 p-4 overflow-y-auto font-mono text-xs" style={{ maxHeight: '300px' }}>
                {agent.outputLines.length === 0 ? (
                  <span className="text-surface-600">No output yet...</span>
                ) : (
                  agent.outputLines.map((line, i) => (
                    <div key={i} className="whitespace-pre-wrap py-0.5">{line}</div>
                  ))
                )}
                <div ref={logEndRef} />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="flex-1 p-4 overflow-y-auto bg-surface-950">
            <div className="font-mono text-xs text-surface-400 leading-relaxed">
              {agent.outputLines.length === 0 ? (
                <span className="text-surface-600">No output yet...</span>
              ) : (
                agent.outputLines.map((line, i) => (
                  <div key={i} className="whitespace-pre-wrap py-0.5 hover:bg-surface-900/50">
                    <span className="text-surface-700 select-none mr-3">{String(i + 1).padStart(4)}</span>
                    {line}
                  </div>
                ))
              )}
              <div ref={logEndRef} />
            </div>
          </div>
        )}

        {activeTab === 'diff' && (
          <div className="flex-1 p-6 overflow-y-auto">
            <DiffViewer diff={relatedSubtask?.errorContext?.diff ?? ''} />
          </div>
        )}
      </div>

      {/* Action bar — approve/reject when needs review */}
      {needsReview && (
        <div className="border-t border-surface-800/50 px-6 py-4">
          <div className="flex items-center gap-4">
            <button
              onClick={handleApprove}
              className="bg-white text-black font-bold text-sm px-6 py-2.5 rounded-md hover:bg-surface-200 transition-colors"
            >
              Approve
            </button>
            <button
              onClick={handleReject}
              className="bg-surface-800 text-white font-bold text-sm px-6 py-2.5 rounded-md hover:bg-surface-700 transition-colors"
            >
              Reject
            </button>

            <div className="flex-1 flex items-center gap-2">
              <input
                type="text"
                value={feedback}
                onChange={(e) => setFeedback(e.target.value)}
                placeholder="Add feedback and retry..."
                className="input-field flex-1"
                onKeyDown={(e) => e.key === 'Enter' && handleRetryWithFeedback()}
              />
              <button
                onClick={handleRetryWithFeedback}
                disabled={!feedback.trim()}
                className="text-sm font-semibold text-surface-400 hover:text-white transition-colors disabled:opacity-30"
              >
                Retry
              </button>
            </div>
          </div>

          {/* Error context */}
          {relatedSubtask?.errorContext && (
            <div className="mt-3 bg-surface-900 border border-surface-800 rounded p-3">
              <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider block mb-1">
                Validation Issue
              </span>
              <p className="text-xs text-surface-400">
                {relatedSubtask.errorContext.vlmAnalysis || 'No details available'}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Progress bar at bottom */}
      <div className="h-1 bg-surface-900">
        <div
          className={`h-full bg-white transition-all duration-500 ${
            agent.status === 'running' ? 'animate-pulse-subtle' : ''
          }`}
          style={{ width: `${agent.progress}%` }}
        />
      </div>
    </div>
  )
}

// ── Sub-components ────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    idle: 'bg-surface-800 text-surface-500',
    running: 'bg-surface-800 text-white',
    validating: 'bg-surface-800 text-surface-300',
    error: 'bg-surface-800 text-surface-400',
    done: 'bg-surface-800 text-surface-400'
  }

  return (
    <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${colors[status] ?? colors.idle}`}>
      {status}
    </span>
  )
}

function ConfidenceMeter({ value }: { value: number }) {
  const width = Math.min(100, Math.max(0, value))
  const color =
    value >= 85 ? 'bg-white' :
    value >= 50 ? 'bg-surface-400' :
    'bg-surface-600'

  return (
    <div className="w-20 h-2 bg-surface-800 rounded-full overflow-hidden">
      <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${width}%` }} />
    </div>
  )
}

const stepStyles: Record<PipelineStep, { color: string; bgColor: string; icon: string }> = {
  queued: { color: 'text-surface-500', bgColor: 'bg-surface-800', icon: '○' },
  coding: { color: 'text-blue-400', bgColor: 'bg-blue-500/10', icon: '{ }' },
  writing: { color: 'text-purple-400', bgColor: 'bg-purple-500/10', icon: '↓' },
  executing: { color: 'text-amber-400', bgColor: 'bg-amber-500/10', icon: '▶' },
  validating: { color: 'text-cyan-400', bgColor: 'bg-cyan-500/10', icon: '✓' },
  approved: { color: 'text-green-400', bgColor: 'bg-green-500/10', icon: '●' },
  rejected: { color: 'text-red-400', bgColor: 'bg-red-500/10', icon: '✕' },
  retrying: { color: 'text-amber-400', bgColor: 'bg-amber-500/10', icon: '↻' },
  error: { color: 'text-red-400', bgColor: 'bg-red-500/10', icon: '!' }
}

const stepLabels: Record<PipelineStep, string> = {
  queued: 'Queued',
  coding: 'Generating Code',
  writing: 'Writing Files',
  executing: 'Executing Code',
  validating: 'Validating Result',
  approved: 'Approved',
  rejected: 'Needs Review',
  retrying: 'Retrying',
  error: 'Error'
}

function PipelineTimeline({ events }: { events: Array<{ step: PipelineStep; message: string; timestamp: number; detail?: string }> }) {
  if (events.length === 0) {
    return <span className="text-surface-600 text-xs">Waiting for pipeline to start...</span>
  }

  return (
    <div className="flex flex-col gap-0">
      {events.map((event, i) => {
        const style = stepStyles[event.step] ?? stepStyles.queued
        const label = stepLabels[event.step] ?? event.step
        const isLast = i === events.length - 1
        const duration = i < events.length - 1
          ? ((events[i + 1].timestamp - event.timestamp) / 1000).toFixed(1)
          : null

        return (
          <div key={i} className="flex gap-3">
            {/* Timeline line + dot */}
            <div className="flex flex-col items-center w-6 shrink-0">
              <div className={`w-3 h-3 rounded-full shrink-0 flex items-center justify-center ${style.bgColor} border ${
                isLast ? 'border-surface-500' : 'border-transparent'
              }`}>
                <div className={`w-1.5 h-1.5 rounded-full ${
                  event.step === 'approved' ? 'bg-green-400' :
                  event.step === 'error' || event.step === 'rejected' ? 'bg-red-400' :
                  event.step === 'retrying' ? 'bg-amber-400' :
                  isLast ? 'bg-white' : 'bg-surface-500'
                }`} />
              </div>
              {!isLast && <div className="w-px flex-1 bg-surface-800 min-h-[24px]" />}
            </div>

            {/* Content */}
            <div className={`pb-4 flex-1 min-w-0 ${isLast ? '' : 'opacity-70'}`}>
              <div className="flex items-center gap-2 mb-0.5">
                <span className={`text-xs font-bold ${style.color}`}>
                  {label}
                </span>
                {duration && (
                  <span className="text-[10px] text-surface-600">{duration}s</span>
                )}
              </div>
              <p className="text-xs text-surface-400 leading-relaxed break-words">
                {event.message}
              </p>
              {event.detail && (
                <pre className="text-[10px] text-surface-500 mt-1 font-mono bg-surface-950 rounded p-2 overflow-x-auto whitespace-pre-wrap break-words">
                  {event.detail}
                </pre>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
