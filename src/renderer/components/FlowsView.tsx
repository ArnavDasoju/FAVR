import { useState } from 'react'
import { useTaskStore } from '../stores/taskStore'
import type { Task } from '@shared/types'

const statusDot: Record<string, string> = {
  queued: 'bg-surface-600',
  chunking: 'bg-surface-500',
  running: 'bg-white status-blink',
  validating: 'bg-surface-300 status-blink',
  retrying: 'bg-surface-300 status-blink',
  needs_review: 'bg-white',
  approved: 'bg-surface-400',
  rejected: 'bg-surface-600'
}

export default function FlowsView() {
  const tasks = useTaskStore((s) => s.tasks)
  const [expandedFlow, setExpandedFlow] = useState<string | null>(null)

  // Auto-expand first task
  if (expandedFlow === null && tasks.length > 0 && !expandedFlow) {
    // Will expand on first click
  }

  const activeCount = tasks.filter((t) =>
    t.status === 'running' || t.status === 'validating' || t.status === 'retrying'
  ).length

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white mb-1">Flows</h1>
          <p className="text-sm text-surface-500">
            {activeCount} active &middot; {tasks.length} total tasks
          </p>
        </div>
      </div>

      {tasks.length === 0 ? (
        <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card p-12 text-center">
          <p className="text-sm text-surface-500">No flows yet. Submit a task from the Dashboard to create one.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {tasks.map((task) => {
            const subtasks = task.subtasks ?? []
            const doneCount = subtasks.filter((s) =>
              s.status === 'approved' || s.status === 'rejected'
            ).length
            const totalCount = Math.max(subtasks.length, 1)
            const progress = Math.round((doneCount / totalCount) * 100)
            const isExpanded = expandedFlow === task.id

            return (
              <div
                key={task.id}
                className="bg-surface-900 border border-surface-800 rounded-card overflow-hidden"
              >
                {/* Flow header */}
                <button
                  onClick={() => setExpandedFlow(isExpanded ? null : task.id)}
                  className="w-full px-5 py-4 flex items-center gap-4 text-left hover:bg-surface-800/30 transition-colors"
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-1">
                      <span className="text-base font-bold text-white truncate">
                        {task.prompt}
                      </span>
                      <span
                        className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded shrink-0 ${
                          task.status === 'running' || task.status === 'validating'
                            ? 'bg-surface-800 text-white'
                            : task.status === 'approved'
                              ? 'bg-surface-800 text-surface-400'
                              : task.status === 'needs_review'
                                ? 'bg-surface-800 text-white'
                                : 'bg-surface-800 text-surface-500'
                        }`}
                      >
                        {task.status}
                      </span>
                    </div>
                    <span className="text-xs text-surface-500">
                      {subtasks.length} subtask{subtasks.length !== 1 ? 's' : ''} &middot;{' '}
                      {task.model?.split('/').pop() ?? 'auto'}
                    </span>
                  </div>

                  <div className="flex items-center gap-6 shrink-0">
                    <div className="flex flex-col items-end gap-1">
                      <span className="text-[10px] font-mono text-surface-500">
                        {doneCount}/{totalCount}
                      </span>
                      <div className="w-24 h-1 bg-surface-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-white rounded-full transition-all"
                          style={{ width: `${progress}%` }}
                        />
                      </div>
                    </div>

                    <span className="text-sm font-bold text-white w-16 text-right">
                      ${(task.cost ?? 0).toFixed(2)}
                    </span>

                    <span className={`text-surface-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
                      &#9662;
                    </span>
                  </div>
                </button>

                {/* Subtasks */}
                {isExpanded && subtasks.length > 0 && (
                  <div className="border-t border-surface-800/50">
                    {subtasks.map((subtask, i) => (
                      <div
                        key={subtask.id}
                        className="px-5 py-3 flex items-center gap-4 border-b border-surface-800/20 last:border-0 hover:bg-surface-800/20 transition-colors"
                      >
                        <span className="text-[10px] font-mono text-surface-600 w-5 text-right shrink-0">
                          {i + 1}
                        </span>

                        <div className={`w-2 h-2 rounded-full shrink-0 ${statusDot[subtask.status] ?? 'bg-surface-600'}`} />

                        <span className="text-sm text-surface-300 flex-1 truncate">
                          {subtask.prompt}
                        </span>

                        <span className="text-[10px] font-bold text-surface-400 uppercase tracking-wider shrink-0">
                          {subtask.model?.split('/').pop() ?? '—'}
                        </span>

                        {subtask.confidence !== null && (
                          <span className={`text-[10px] font-mono shrink-0 ${
                            subtask.confidence >= 85 ? 'text-surface-400' : 'text-surface-500'
                          }`}>
                            {subtask.confidence}%
                          </span>
                        )}

                        <span className={`text-[10px] font-bold uppercase tracking-wider shrink-0 ${
                          statusDot[subtask.status] ? '' : ''
                        } ${
                          subtask.status === 'approved' ? 'text-surface-400' :
                          subtask.status === 'needs_review' ? 'text-white' :
                          subtask.status === 'running' ? 'text-white' :
                          'text-surface-600'
                        }`}>
                          {subtask.status === 'needs_review' ? 'review' : subtask.status}
                        </span>
                      </div>
                    ))}
                  </div>
                )}

                {/* No subtasks yet */}
                {isExpanded && subtasks.length === 0 && (
                  <div className="border-t border-surface-800/50 px-5 py-4">
                    <span className="text-xs text-surface-500">
                      {task.status === 'chunking' ? 'Breaking task into subtasks...' : 'No subtasks'}
                    </span>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
