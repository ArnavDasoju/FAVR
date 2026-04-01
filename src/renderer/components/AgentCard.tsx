import type { Agent, FeedMode } from '@shared/types'

const statusColors: Record<string, string> = {
  idle: 'bg-surface-600',
  running: 'bg-white status-blink',
  validating: 'bg-surface-400 status-blink',
  error: 'bg-white',
  done: 'bg-white'
}

const statusLabels: Record<string, string> = {
  idle: 'IDLE',
  running: 'RUNNING',
  validating: 'VALIDATING',
  error: 'ERROR',
  done: 'COMPLETE'
}

const feedModeLabels: Record<FeedMode, string> = {
  terminal: 'Terminal',
  preview: 'Preview',
  screenshot: 'Screenshot'
}

interface AgentCardProps {
  agent: Agent
  onClick?: () => void
}

export default function AgentCard({ agent, onClick }: AgentCardProps) {
  // Auto-select feed mode: show preview during validating, terminal during running
  const effectiveFeedMode: FeedMode =
    agent.status === 'validating' && agent.devServerUrl
      ? 'preview'
      : agent.validationScreenshot && (agent.status === 'done' || agent.status === 'error')
        ? 'screenshot'
        : agent.feedMode

  return (
    <div
      className="bg-surface-900 border border-surface-800 rounded-card text-left
        hover:border-surface-600 transition-colors cursor-pointer flex flex-col w-full"
    >
      {/* Header — name, model, status */}
      <div className="px-4 pt-4 pb-3 flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <span className="text-sm font-bold text-white truncate">{agent.name}</span>
          <span className="text-[10px] font-mono text-surface-500 uppercase tracking-wider">
            {agent.model.split('/').pop()}
          </span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0 bg-surface-950 px-2.5 py-1 rounded">
          <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${statusColors[agent.status]}`} />
          <span className="text-[10px] font-bold tracking-wider text-surface-400 uppercase">
            {statusLabels[agent.status]}
          </span>
        </div>
      </div>

      {/* Progress bar */}
      <div className="px-4 pb-3">
        <div className="w-full h-1 bg-surface-800 rounded-full overflow-hidden">
          <div
            className={`h-full bg-white rounded-full transition-all duration-500 ${
              agent.status === 'running' ? 'animate-pulse-subtle' : ''
            }`}
            style={{ width: `${agent.progress}%` }}
          />
        </div>
      </div>

      {/* Feed area */}
      <div className="mx-3 mb-3 rounded bg-surface-950 aspect-video overflow-hidden relative">
        {/* Feed mode indicator */}
        <div className="absolute top-2 left-2 z-10 flex items-center gap-1 bg-surface-950/80 backdrop-blur-sm px-2 py-0.5 rounded">
          <span className="text-[9px] font-bold text-surface-500 uppercase tracking-wider">
            {feedModeLabels[effectiveFeedMode]}
          </span>
        </div>

        {/* Live preview — embedded webview of the dev server */}
        {effectiveFeedMode === 'preview' && agent.devServerUrl ? (
          <div className="w-full h-full relative">
            <webview
              src={agent.devServerUrl}
              className="w-full h-full border-0"
              // @ts-expect-error webview is an Electron-specific element
              disablewebsecurity="true"
              allowpopups={false}
            />
            {/* Overlay to prevent interaction in card view, click goes to expand */}
            <div
              className="absolute inset-0 cursor-pointer"
              onClick={onClick}
            />
            {/* Validating indicator */}
            {agent.status === 'validating' && (
              <div className="absolute bottom-2 right-2 flex items-center gap-1.5 bg-surface-950/90 px-2.5 py-1 rounded">
                <div className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                <span className="text-[9px] font-bold text-surface-300 uppercase tracking-wider">
                  Checking...
                </span>
              </div>
            )}
          </div>
        ) : effectiveFeedMode === 'screenshot' && (agent.validationScreenshot || agent.lastFrame) ? (
          /* Validation screenshot — before/after from the validation loop */
          <div className="w-full h-full relative" onClick={onClick}>
            <img
              src={agent.validationScreenshot || agent.lastFrame || ''}
              alt="Validation result"
              className="w-full h-full object-cover"
            />
            {agent.status === 'done' && (
              <div className="absolute bottom-2 right-2 flex items-center gap-1.5 bg-surface-950/90 px-2.5 py-1 rounded">
                <span className="text-[9px] font-bold text-white uppercase tracking-wider">
                  Passed
                </span>
              </div>
            )}
            {agent.status === 'error' && (
              <div className="absolute bottom-2 right-2 flex items-center gap-1.5 bg-surface-950/90 px-2.5 py-1 rounded">
                <span className="text-[9px] font-bold text-surface-400 uppercase tracking-wider">
                  Failed
                </span>
              </div>
            )}
          </div>
        ) : agent.lastFrame ? (
          /* Puppeteer screenshot frame */
          <img
            src={agent.lastFrame}
            alt="Agent feed"
            className="w-full h-full object-cover cursor-pointer"
            onClick={onClick}
          />
        ) : agent.status === 'running' || agent.outputLines.length > 0 ? (
          /* Terminal output */
          <div className="terminal-output text-surface-500 p-3 h-full overflow-hidden" onClick={onClick}>
            {agent.outputLines.slice(-8).map((line, i) => (
              <div key={i} className="truncate">
                {line}
              </div>
            ))}
            {agent.outputLines.length === 0 && (
              <span className="text-surface-600">Waiting for output...</span>
            )}
          </div>
        ) : (
          <div className="h-full flex items-center justify-center" onClick={onClick}>
            <span className="text-surface-700 text-[10px] font-mono uppercase tracking-[0.2em]">
              No Feed
            </span>
          </div>
        )}
      </div>

      {/* Current task */}
      {agent.currentTask && (
        <div className="px-4 pb-4" onClick={onClick}>
          <p className="text-xs text-surface-400 truncate">
            {agent.currentTask}
          </p>
        </div>
      )}
    </div>
  )
}
