import { useState } from 'react'
import { useVerifyStore, type VerifyStep, type VerifyStepStatus } from '../stores/verifyStore'

const STATUS_COLORS: Record<VerifyStepStatus, string> = {
  pending: 'text-surface-500 border-surface-700 bg-surface-900',
  running: 'text-blue-300 border-blue-500/40 bg-blue-500/10',
  pass: 'text-green-300 border-green-500/40 bg-green-500/10',
  fail: 'text-red-300 border-red-500/40 bg-red-500/10',
  skip: 'text-surface-400 border-surface-700 bg-surface-900/50'
}

const STATUS_LABEL: Record<VerifyStepStatus, string> = {
  pending: 'Pending',
  running: 'Running',
  pass: 'Pass',
  fail: 'Fail',
  skip: 'Skip'
}

function StatusIcon({ status }: { status: VerifyStepStatus }) {
  if (status === 'running')
    return <div className="w-3 h-3 rounded-full border border-blue-400 border-t-transparent animate-spin" />
  if (status === 'pass')
    return (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={3} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
    )
  if (status === 'fail')
    return (
      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={3} viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
      </svg>
    )
  if (status === 'skip') return <span className="text-xs">—</span>
  return <div className="w-2 h-2 rounded-full bg-surface-600" />
}

function StepRow({ step }: { step: VerifyStep }) {
  const [open, setOpen] = useState(false)
  const hasOutput = !!step.output
  return (
    <div className={`rounded-btn border ${STATUS_COLORS[step.status]}`}>
      <button
        type="button"
        onClick={() => hasOutput && setOpen(v => !v)}
        className="w-full flex items-center justify-between px-3 py-2 text-left"
        disabled={!hasOutput}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <StatusIcon status={step.status} />
          <div className="min-w-0">
            <div className="text-xs font-semibold truncate">{step.label}</div>
            {step.command && (
              <div className="text-[10px] font-mono text-surface-500 truncate">{step.command}</div>
            )}
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {step.durationMs !== undefined && (
            <span className="text-[10px] font-mono text-surface-500">
              {(step.durationMs / 1000).toFixed(1)}s
            </span>
          )}
          <span className="text-[10px] font-black uppercase tracking-wider">
            {STATUS_LABEL[step.status]}
          </span>
          {hasOutput && (
            <svg
              className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              strokeWidth={2.5}
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          )}
        </div>
      </button>
      {open && hasOutput && (
        <pre className="px-3 py-2 border-t border-surface-800 text-[10px] font-mono text-surface-300 whitespace-pre-wrap break-all max-h-64 overflow-y-auto bg-surface-950/50">
          {step.output}
        </pre>
      )}
    </div>
  )
}

export default function VerifyPanel() {
  const { phase, steps, ecosystem, allPassed, durationMs, open, setOpen } = useVerifyStore()
  if (!open) return null

  const passed = steps.filter(s => s.status === 'pass').length
  const failed = steps.filter(s => s.status === 'fail').length
  const running = phase === 'running'

  return (
    <div className="mb-4 rounded-btn border border-surface-700 bg-surface-900/60 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-surface-800">
        <div className="flex items-center gap-3">
          <div className="text-xs font-black uppercase tracking-wider text-white">
            Verification
          </div>
          {ecosystem && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-800 text-surface-300">
              {ecosystem}
            </span>
          )}
          {phase === 'complete' && (
            <span
              className={`text-[10px] font-black uppercase tracking-wider px-2 py-0.5 rounded ${
                allPassed
                  ? 'bg-green-500/10 text-green-300 border border-green-500/40'
                  : 'bg-red-500/10 text-red-300 border border-red-500/40'
              }`}
            >
              {allPassed ? 'All passed' : `${failed} failed`}
            </span>
          )}
          {running && (
            <span className="text-[10px] font-mono text-blue-300">
              {passed}/{steps.length} passed…
            </span>
          )}
          {phase === 'complete' && durationMs > 0 && (
            <span className="text-[10px] font-mono text-surface-500">
              {(durationMs / 1000).toFixed(1)}s total
            </span>
          )}
        </div>
        <button
          onClick={() => setOpen(false)}
          className="text-surface-500 hover:text-white text-xs"
          disabled={running}
        >
          ✕
        </button>
      </div>
      <div className="p-3 space-y-2">
        {steps.length === 0 ? (
          <div className="text-xs text-surface-500 text-center py-4">Starting verification…</div>
        ) : (
          steps.map(s => <StepRow key={s.id} step={s} />)
        )}
      </div>
    </div>
  )
}

export function useRunVerification(codebasePath: string) {
  return async () => {
    if (!codebasePath) return
    useVerifyStore.getState().reset()
    useVerifyStore.getState().setOpen(true)
    try {
      await window.api.invoke('verify:run', { codebasePath })
    } catch (err) {
      console.error('[verify] failed', err)
    }
  }
}
