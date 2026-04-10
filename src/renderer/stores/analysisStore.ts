import { create } from 'zustand'
import type {
  FavrAnalysisResult, FavrAnalysisProgress, AnalysisPhase,
  FavrVulnerability, FavrService
} from '../../shared/types'

interface AnalysisStore {
  // Analysis state
  result: FavrAnalysisResult | null
  phase: AnalysisPhase
  progress: number
  message: string
  error: string | null

  // Mode
  mode: 'analysis' | 'remediation'

  // Whether results have been viewed (skip re-entry animations)
  hasSeenResults: boolean

  // Selected items
  selectedVulnId: string | null
  selectedServiceId: string | null
  selectedParetoId: string | null

  // Document paths
  uploadedFiles: string[]

  // Actions
  setResult: (result: FavrAnalysisResult) => void
  setProgress: (progress: FavrAnalysisProgress) => void
  setError: (error: string) => void
  setMode: (mode: 'analysis' | 'remediation') => void
  markResultsSeen: () => void
  selectVuln: (id: string | null) => void
  selectService: (id: string | null) => void
  selectPareto: (id: string | null) => void
  setUploadedFiles: (files: string[]) => void
  reset: () => void

  // Computed helpers
  getVulnById: (id: string) => FavrVulnerability | undefined
  getServiceById: (id: string) => FavrService | undefined
  getOptimalVulns: () => FavrVulnerability[]
  getFrontierSolutions: () => FavrAnalysisResult['pareto']['solutions']
}

export const useAnalysisStore = create<AnalysisStore>((set, get) => ({
  result: null,
  phase: 'idle',
  progress: 0,
  message: '',
  error: null,
  mode: 'analysis',
  hasSeenResults: false,
  selectedVulnId: null,
  selectedServiceId: null,
  selectedParetoId: null,
  uploadedFiles: [],

  setResult: (result) => set({ result, phase: 'complete', progress: 100, error: null, hasSeenResults: false }),
  markResultsSeen: () => set({ hasSeenResults: true }),
  setProgress: (p) => set({ phase: p.phase as AnalysisPhase, progress: p.progress, message: p.message }),
  setError: (error) => set({ error, phase: 'error' }),
  setMode: (mode) => set({ mode }),
  selectVuln: (id) => set({ selectedVulnId: id }),
  selectService: (id) => set({ selectedServiceId: id }),
  selectPareto: (id) => set({ selectedParetoId: id }),
  setUploadedFiles: (files) => set({ uploadedFiles: files }),
  reset: () => set({ result: null, phase: 'idle', progress: 0, message: '', error: null, hasSeenResults: false }),

  getVulnById: (id) => get().result?.graph.vulnerabilities.find(v => v.id === id),
  getServiceById: (id) => get().result?.graph.services.find(s => s.id === id),

  getOptimalVulns: () => {
    const r = get().result
    if (!r) return []
    const vulnMap = new Map(r.graph.vulnerabilities.map(v => [v.id, v]))
    return r.simulation.optimalOrder
      .map(id => vulnMap.get(id))
      .filter((v): v is FavrVulnerability => !!v)
  },

  getFrontierSolutions: () => {
    const r = get().result
    if (!r) return []
    const frontierSet = new Set(r.pareto.frontierIds)
    return r.pareto.solutions.filter(s => frontierSet.has(s.id))
  }
}))
