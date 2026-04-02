/**
 * PiPWindow — Floating mini window showing active agent status.
 *
 * Shows: agent name, progress bar, mini live feed.
 * Draggable, always on top (handled by main process).
 * Click to expand back to main window.
 */

import { useAgentStore } from '../stores/agentStore'

interface PiPWindowProps {
  onExpand: (agentId: string) => void
}

export default function PiPWindow({ onExpand }: PiPWindowProps) {
  const agents = useAgentStore((s) => Object.values(s.agents))

  // Find the most interesting agent to show (running > validating > done)
  const activeAgent =
    agents.find((a) => a.status === 'running') ??
    agents.find((a) => a.status === 'validating') ??
    agents.find((a) => a.status === 'done' || a.status === 'error')

  if (!activeAgent) return null

  return (
    <div
      className="fixed bottom-6 right-6 z-50 w-64 bg-surface-900 border border-surface-800 rounded-card shadow-2xl overflow-hidden cursor-pointer hover:border-surface-600 transition-colors"
      onClick={() => onExpand(activeAgent.id)}
    >
      {/* Mini feed */}
      <div className="aspect-video bg-surface-950 overflow-hidden relative">
        {activeAgent.lastFrame || activeAgent.validationScreenshot ? (
          <img
            src={activeAgent.validationScreenshot || activeAgent.lastFrame || ''}
            alt="Mini feed"
            className="w-full h-full object-cover"
          />
        ) : activeAgent.outputLines.length > 0 ? (
          <div className="terminal-output text-surface-600 p-2 h-full overflow-hidden text-[8px]">
            {activeAgent.outputLines.slice(-4).map((line, i) => (
              <div key={i} className="truncate">{line}</div>
            ))}
          </div>
        ) : (
          <div className="h-full flex items-center justify-center">
            <span className="text-surface-800 text-[8px] font-mono uppercase">No Feed</span>
          </div>
        )}

        {/* Status indicator */}
        {activeAgent.status === 'running' && (
          <div className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-white animate-pulse" />
        )}
        {activeAgent.status === 'validating' && (
          <div className="absolute top-1.5 right-1.5 flex items-center gap-1 bg-surface-950/80 px-1.5 py-0.5 rounded">
            <div className="w-1.5 h-1.5 rounded-full bg-surface-400 animate-pulse" />
            <span className="text-[7px] font-bold text-surface-400 uppercase">Checking</span>
          </div>
        )}
      </div>

      {/* Info bar */}
      <div className="px-3 py-2">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[10px] font-bold text-white truncate">{activeAgent.name}</span>
          <span className="text-[8px] font-bold text-surface-500 uppercase tracking-wider">
            {activeAgent.status}
          </span>
        </div>

        {/* Progress bar */}
        <div className="w-full h-1 bg-surface-800 rounded-full overflow-hidden">
          <div
            className={`h-full bg-white rounded-full transition-all duration-500 ${
              activeAgent.status === 'running' ? 'animate-pulse-subtle' : ''
            }`}
            style={{ width: `${activeAgent.progress}%` }}
          />
        </div>
      </div>
    </div>
  )
}
