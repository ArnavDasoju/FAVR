import { create } from 'zustand'

export type VerifyStepStatus = 'pending' | 'running' | 'pass' | 'fail' | 'skip'

export interface VerifyStep {
  id: string
  label: string
  status: VerifyStepStatus
  output?: string
  durationMs?: number
  command?: string
}

export type VerifyPhase = 'idle' | 'running' | 'complete'

interface VerifyStore {
  phase: VerifyPhase
  steps: VerifyStep[]
  ecosystem: string
  allPassed: boolean
  durationMs: number
  open: boolean
  setOpen: (open: boolean) => void
  start: (steps: VerifyStep[], ecosystem: string) => void
  updateStep: (step: VerifyStep) => void
  complete: (allPassed: boolean, durationMs: number) => void
  reset: () => void
}

export const useVerifyStore = create<VerifyStore>(set => ({
  phase: 'idle',
  steps: [],
  ecosystem: '',
  allPassed: false,
  durationMs: 0,
  open: false,
  setOpen: open => set({ open }),
  start: (steps, ecosystem) =>
    set({ phase: 'running', steps, ecosystem, allPassed: false, durationMs: 0, open: true }),
  updateStep: step =>
    set(state => {
      const next = state.steps.map(s => (s.id === step.id ? { ...s, ...step } : s))
      return { steps: next }
    }),
  complete: (allPassed, durationMs) => set({ phase: 'complete', allPassed, durationMs }),
  reset: () =>
    set({ phase: 'idle', steps: [], ecosystem: '', allPassed: false, durationMs: 0, open: false })
}))
