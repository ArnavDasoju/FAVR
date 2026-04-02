import type { Agent, FeedMode, PipelineStep } from '@shared/types'

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

const pipelineStepConfig: Record<PipelineStep, { label: string; icon: string; color: string }> = {
  queued: { label: 'Queued', icon: '○', color: 'text-surface-500' },
  coding: { label: 'Coding', icon: '◐', color: 'text-white' },
  writing: { label: 'Writing Files', icon: '◑', color: 'text-white' },
  executing: { label: 'Executing', icon: '◒', color: 'text-white' },
  validating: { label: 'Validating', icon: '◓', color: 'text-surface-400' },
  approved: { label: 'Approved', icon: '●', color: 'text-green-400' },
  rejected: { label: 'Needs Review', icon: '●', color: 'text-red-400' },
  retrying: { label: 'Retrying', icon: '↻', color: 'text-amber-400' },
  error: { label: 'Error', icon: '✕', color: 'text-red-400' }
}

const PIPELINE_ORDER: PipelineStep[] = ['coding', 'writing', 'executing', 'validating']

interface AgentCardProps {
  agent: Agent
  onClick?: () => void
}

export default function AgentCard({ agent, onClick }: AgentCardProps) {
  const effectiveFeedMode: FeedMode =
    agent.status === 'validating' && agent.devServerUrl
      ? 'preview'
      : agent.validationScreenshot && (agent.status === 'done' || agent.status === 'error')
        ? 'screenshot'
        : agent.feedMode

  // Get the latest pipeline step
  const pipeline = agent.pipeline || []
  const latestStep = pipeline.length > 0 ? pipeline[pipeline.length - 1] : null
  const completedSteps = new Set(pipeline.map((e) => e.step))

  // Determine final status from pipeline
  const finalStep = latestStep?.step
  const isApproved = finalStep === 'approved'
  const isRejected = finalStep === 'rejected' || finalStep === 'error'
  const isRetrying = finalStep === 'retrying'

  return (
    <div
      className={`bg-surface-900 border rounded-card text-left
        hover:border-surface-600 transition-colors cursor-pointer flex flex-col w-full
        ${isApproved ? 'border-green-500/30' : isRejected ? 'border-red-500/30' : isRetrying ? 'border-amber-500/30' : 'border-surface-800'}`}
    >
      {/* Header */}
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

      {/* Pipeline tracker */}
      {pipeline.length > 0 && (
        <div className="px-4 pb-3">
          {/* Step dots */}
          <div className="flex items-center gap-1 mb-2">
            {PIPELINE_ORDER.map((step) => {
              const done = completedSteps.has(step)
              const active = latestStep?.step === step
              const cfg = pipelineStepConfig[step]
              return (
                <div key={step} className="flex items-center gap-1 flex-1">
                  <div
                    className={`w-full h-1 rounded-full transition-all duration-300 ${
                      done
                        ? isApproved
                          ? 'bg-green-500'
                          : isRejected
                            ? 'bg-red-500'
                            : 'bg-white'
                        : active
                          ? 'bg-white/50 animate-pulse'
                          : 'bg-surface-800'
                    }`}
                  />
                </div>
              )
            })}
          </div>

          {/* Current step label */}
          {latestStep && (
            <div className="flex items-center gap-2">
              <span className={`text-[10px] font-bold ${pipelineStepConfig[latestStep.step]?.color ?? 'text-surface-400'}`}>
                {pipelineStepConfig[latestStep.step]?.icon}{' '}
                {pipelineStepConfig[latestStep.step]?.label ?? latestStep.step}
              </span>
              <span className="text-[10px] text-surface-600 truncate flex-1">
                {latestStep.message}
              </span>
            </div>
          )}
        </div>
      )}

      {/* Progress bar (only show if no pipeline yet) */}
      {pipeline.length === 0 && (
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
      )}

      {/* Feed area */}
      <div className="mx-3 mb-3 rounded bg-surface-950 overflow-hidden relative" style={{ minHeight: '120px' }}>
        {/* Terminal output */}
        {agent.status === 'running' || agent.outputLines.length > 0 ? (
          <div className="terminal-output text-surface-500 p-3 h-full overflow-hidden" onClick={onClick}>
            {agent.outputLines.slice(-8).map((line, i) => (
              <div key={i} className="truncate text-[11px]">
                {line}
              </div>
            ))}
            {agent.outputLines.length === 0 && (
              <span className="text-surface-600">Waiting for output...</span>
            )}
          </div>
        ) : (
          <div className="h-full flex items-center justify-center p-8" onClick={onClick}>
            <span className="text-surface-700 text-[10px] font-mono uppercase tracking-[0.2em]">
              No Feed
            </span>
          </div>
        )}
      </div>

      {/* Pipeline history — show all steps */}
      {pipeline.length > 1 && (
        <div className="px-4 pb-3">
          <div className="flex flex-col gap-1">
            {pipeline.slice(-5).map((event, i) => {
              const cfg = pipelineStepConfig[event.step]
              const isLast = i === Math.min(pipeline.length, 5) - 1
              return (
                <div key={i} className={`flex items-center gap-2 ${isLast ? '' : 'opacity-50'}`}>
                  <span className={`text-[9px] font-bold ${cfg?.color ?? 'text-surface-500'}`}>
                    {cfg?.icon}
                  </span>
                  <span className={`text-[9px] ${isLast ? 'text-surface-300' : 'text-surface-600'} truncate`}>
                    {cfg?.label}: {event.message}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}

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
