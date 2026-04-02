import { create } from 'zustand'
import type { Agent, AgentStatus, PipelineEvent } from '@shared/types'

interface AgentStore {
  agents: Record<string, Agent>
  activeAgentId: string | null
  addAgent: (agent: Agent) => void
  updateAgent: (id: string, updates: Partial<Agent>) => void
  removeAgent: (id: string) => void
  setActiveAgent: (id: string | null) => void
  appendOutput: (id: string, line: string) => void
  appendPipeline: (id: string, event: PipelineEvent) => void
  setFrame: (id: string, frame: string) => void
  setStatus: (id: string, status: AgentStatus, progress: number) => void
}

export const useAgentStore = create<AgentStore>((set) => ({
  agents: {},
  activeAgentId: null,

  addAgent: (agent) =>
    set((s) => ({ agents: { ...s.agents, [agent.id]: agent } })),

  updateAgent: (id, updates) =>
    set((s) => ({
      agents: {
        ...s.agents,
        [id]: s.agents[id] ? { ...s.agents[id], ...updates } : s.agents[id]
      }
    })),

  removeAgent: (id) =>
    set((s) => {
      const { [id]: _, ...rest } = s.agents
      return { agents: rest }
    }),

  setActiveAgent: (id) => set({ activeAgentId: id }),

  appendOutput: (id, line) =>
    set((s) => {
      const agent = s.agents[id]
      if (!agent) return s
      const outputLines = [...agent.outputLines, line].slice(-200)
      return { agents: { ...s.agents, [id]: { ...agent, outputLines } } }
    }),

  appendPipeline: (id, event) =>
    set((s) => {
      const agent = s.agents[id]
      if (!agent) return s
      const pipeline = [...(agent.pipeline || []), event].slice(-20)
      return { agents: { ...s.agents, [id]: { ...agent, pipeline } } }
    }),

  setFrame: (id, frame) =>
    set((s) => {
      const agent = s.agents[id]
      if (!agent) return s
      return { agents: { ...s.agents, [id]: { ...agent, lastFrame: frame } } }
    }),

  setStatus: (id, status, progress) =>
    set((s) => {
      const agent = s.agents[id]
      if (!agent) return s
      return { agents: { ...s.agents, [id]: { ...agent, status, progress } } }
    })
}))
