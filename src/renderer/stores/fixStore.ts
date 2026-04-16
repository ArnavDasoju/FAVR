import { create } from 'zustand'

export type FixPhase = 'idle' | 'patching' | 'done'

export interface FixVulnRow {
  index: number
  cveId: string
  title: string
  affectedPackage: string
  patchedVersion: string
  severity: string
  complexity: 'low' | 'medium' | 'high'
  model: string
  displayName: string
  provider: string
  taskType: string
  reasoning: string
  status: 'pending' | 'running' | 'done' | 'failed'
  agentId: string | null
  changedFiles: string[]
  error: string | null
}

interface FixStore {
  phase: FixPhase
  vulns: FixVulnRow[]
  canUndo: boolean
  setPhase: (phase: FixPhase) => void
  setCanUndo: (canUndo: boolean) => void
  reset: () => void
  upsertVulnStart: (d: {
    index: number; cveId: string; title: string; affectedPackage: string
    patchedVersion: string; severity: string; complexity: 'low' | 'medium' | 'high'; model: string
    displayName?: string; provider?: string; taskType?: string; reasoning?: string
  }) => void
  markVulnDone: (d: {
    index: number; success: boolean; agentId?: string
    changedFiles?: string[]; error?: string
  }) => void
}

function emptyRow(index: number): FixVulnRow {
  return {
    index, cveId: '', title: '', affectedPackage: '', patchedVersion: '',
    severity: 'low', complexity: 'low', model: '', displayName: '', provider: '',
    taskType: '', reasoning: '', status: 'pending',
    agentId: null, changedFiles: [], error: null
  }
}

export const useFixStore = create<FixStore>(set => ({
  phase: 'idle',
  vulns: [],
  canUndo: false,
  setPhase: phase => set({ phase }),
  setCanUndo: canUndo => set({ canUndo }),
  reset: () => set({ phase: 'idle', vulns: [], canUndo: false }),
  upsertVulnStart: d => set(state => {
    const next = [...state.vulns]
    while (next.length <= d.index) next.push(emptyRow(next.length))
    next[d.index] = {
      ...next[d.index],
      index: d.index,
      cveId: d.cveId,
      title: d.title,
      affectedPackage: d.affectedPackage,
      patchedVersion: d.patchedVersion,
      severity: d.severity,
      complexity: d.complexity,
      model: d.model,
      displayName: d.displayName ?? d.model.split('/').pop() ?? d.model,
      provider: d.provider ?? '',
      taskType: d.taskType ?? '',
      reasoning: d.reasoning ?? '',
      status: 'running'
    }
    return { vulns: next }
  }),
  markVulnDone: d => set(state => {
    const next = [...state.vulns]
    if (next[d.index]) {
      next[d.index] = {
        ...next[d.index],
        status: d.success ? 'done' : 'failed',
        agentId: d.agentId ?? null,
        changedFiles: d.changedFiles ?? [],
        error: d.error ?? null
      }
    }
    return { vulns: next }
  })
}))
