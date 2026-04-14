import { create } from 'zustand'
import type { FavrAgentAssignment } from '../../shared/types'

export type WorkspaceStatus = 'idle' | 'configuring' | 'running' | 'paused' | 'complete' | 'cancelled'

export interface ActiveAgent {
  agentId: string
  vulnId: string
  cveId: string
  model: string
  progress: number
  status: 'running' | 'done' | 'error'
  outputLines: string[]
  changedFiles: string[]
  estimatedCost: number
  actualCost: number
  durationMs: number
}

export interface CompletedVuln {
  vulnId: string
  cveId: string
  success: boolean
  cost: number
  model: string
  changedFiles: string[]
  durationMs: number
  error?: string
}

interface WorkspaceStore {
  // Session
  sessionId: string | null
  status: WorkspaceStatus

  // Budget
  totalBudget: number
  spent: number

  // Assignments from optimizer
  assignments: FavrAgentAssignment[]

  // Live agents
  activeAgents: Record<string, ActiveAgent>

  // Results
  completed: CompletedVuln[]
  skippedVulns: string[]

  // Config inputs (pre-launch)
  budgetInput: number
  maxConcurrent: number
  preferFree: boolean

  // Timing
  startedAt: number | null
  completedAt: number | null

  // Stats from optimizer preview
  expectedFixRate: number
  savingsVsNaive: number

  // Actions
  configure: () => void
  setConfig: (config: { budgetInput?: number; maxConcurrent?: number; preferFree?: boolean }) => void
  setAssignments: (assignments: FavrAgentAssignment[], meta: { expectedFixRate: number; savingsVsNaive: number; skippedVulns: string[] }) => void

  startSession: (sessionId: string) => void
  agentSpawned: (data: { agentId: string; vulnId: string; cveId: string; model: string; estimatedCost: number }) => void
  agentProgress: (agentId: string, progress: number, line: string) => void
  agentDone: (data: { agentId: string; vulnId: string; cveId: string; success: boolean; actualCost: number; changedFiles: string[]; durationMs: number; error?: string }) => void
  agentSkipped: (vulnId: string) => void
  budgetUpdate: (spent: number, remaining: number) => void
  sessionComplete: (data: { succeeded: number; failed: number; skipped: number; totalSpent: number }) => void
  sessionPaused: () => void
  sessionResumed: () => void
  sessionCancelled: () => void

  reset: () => void
}

const initialState = {
  sessionId: null as string | null,
  status: 'idle' as WorkspaceStatus,
  totalBudget: 10,
  spent: 0,
  assignments: [] as FavrAgentAssignment[],
  activeAgents: {} as Record<string, ActiveAgent>,
  completed: [] as CompletedVuln[],
  skippedVulns: [] as string[],
  budgetInput: 10,
  maxConcurrent: 3,
  preferFree: true,
  startedAt: null as number | null,
  completedAt: null as number | null,
  expectedFixRate: 0,
  savingsVsNaive: 0,
}

export const useWorkspaceStore = create<WorkspaceStore>((set) => ({
  ...initialState,

  configure: () => set({ status: 'configuring' }),

  setConfig: (config) => set((s) => ({
    budgetInput: config.budgetInput ?? s.budgetInput,
    maxConcurrent: config.maxConcurrent ?? s.maxConcurrent,
    preferFree: config.preferFree ?? s.preferFree,
  })),

  setAssignments: (assignments, meta) => set({
    assignments,
    expectedFixRate: meta.expectedFixRate,
    savingsVsNaive: meta.savingsVsNaive,
    skippedVulns: meta.skippedVulns,
  }),

  startSession: (sessionId) => set({
    sessionId,
    status: 'running',
    startedAt: Date.now(),
    completedAt: null,
    spent: 0,
    completed: [],
    activeAgents: {},
  }),

  agentSpawned: (data) => set((s) => ({
    activeAgents: {
      ...s.activeAgents,
      [data.agentId]: {
        agentId: data.agentId,
        vulnId: data.vulnId,
        cveId: data.cveId,
        model: data.model,
        progress: 0,
        status: 'running',
        outputLines: [],
        changedFiles: [],
        estimatedCost: data.estimatedCost,
        actualCost: 0,
        durationMs: 0,
      }
    }
  })),

  agentProgress: (agentId, progress, line) => set((s) => {
    const agent = s.activeAgents[agentId]
    if (!agent) return s
    return {
      activeAgents: {
        ...s.activeAgents,
        [agentId]: {
          ...agent,
          progress,
          outputLines: [...agent.outputLines, line].slice(-100),
        }
      }
    }
  }),

  agentDone: (data) => set((s) => {
    const { [data.agentId]: doneAgent, ...restAgents } = s.activeAgents
    return {
      activeAgents: restAgents,
      completed: [...s.completed, {
        vulnId: data.vulnId,
        cveId: data.cveId,
        success: data.success,
        cost: data.actualCost,
        model: doneAgent?.model ?? '',
        changedFiles: data.changedFiles,
        durationMs: data.durationMs,
        error: data.error,
      }],
    }
  }),

  agentSkipped: (vulnId) => set((s) => ({
    skippedVulns: [...s.skippedVulns, vulnId],
  })),

  budgetUpdate: (spent) => set({ spent }),

  sessionComplete: () => set({ status: 'complete', completedAt: Date.now() }),

  sessionPaused: () => set({ status: 'paused' }),
  sessionResumed: () => set({ status: 'running' }),
  sessionCancelled: () => set({ status: 'cancelled', completedAt: Date.now() }),

  reset: () => set({ ...initialState }),
}))
