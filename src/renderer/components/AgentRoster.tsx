import { useState } from 'react'
import type { Agent } from '@shared/types'

interface AgentConfig {
  id: string
  name: string
  model: string
  type: 'cloud' | 'local' | 'ide'
  costPer1kTokens: number
  specialty: string
  enabled: boolean
}

const defaultRoster: AgentConfig[] = [
  {
    id: 'claude',
    name: 'Claude Sonnet',
    model: 'anthropic/claude-sonnet-4.6',
    type: 'cloud',
    costPer1kTokens: 0.003,
    specialty: 'Complex logic, architecture, reasoning',
    enabled: true
  },
  {
    id: 'gpt',
    name: 'GPT-5.4',
    model: 'openai/gpt-5.4',
    type: 'cloud',
    costPer1kTokens: 0.005,
    specialty: 'Broad tasks, refactoring, testing',
    enabled: true
  },
  {
    id: 'ollama',
    name: 'Ollama Local',
    model: 'ollama/llama3',
    type: 'local',
    costPer1kTokens: 0,
    specialty: 'Simple tasks, indexing, privacy',
    enabled: true
  },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    model: 'deepseek/deepseek-chat',
    type: 'cloud',
    costPer1kTokens: 0.001,
    specialty: 'Code generation, fast iteration',
    enabled: false
  }
]

export default function AgentRoster() {
  const [roster, setRoster] = useState<AgentConfig[]>(defaultRoster)
  const [editingSpecialty, setEditingSpecialty] = useState<string | null>(null)

  const toggleAgent = (id: string) => {
    setRoster((prev) =>
      prev.map((a) => (a.id === id ? { ...a, enabled: !a.enabled } : a))
    )
  }

  const updateSpecialty = (id: string, specialty: string) => {
    setRoster((prev) =>
      prev.map((a) => (a.id === id ? { ...a, specialty } : a))
    )
    setEditingSpecialty(null)
  }

  const enabledCount = roster.filter((a) => a.enabled).length
  const totalCost = roster
    .filter((a) => a.enabled)
    .reduce((sum, a) => sum + a.costPer1kTokens, 0)

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold text-white mb-1">Agent Roster</h1>
          <p className="text-sm text-surface-500">
            {enabledCount} agents active &middot; Manage who works on your tasks
          </p>
        </div>
        <button className="px-5 py-2.5 bg-white text-black text-sm font-bold rounded-btn hover:bg-surface-200 transition-colors uppercase tracking-wide">
          + Add Agent
        </button>
      </div>

      {/* Roster grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {roster.map((agent) => (
          <div
            key={agent.id}
            className={`bg-surface-900 border rounded-card p-5 flex flex-col gap-4 transition-all ${
              agent.enabled
                ? 'border-surface-700'
                : 'border-surface-800/50 opacity-50'
            }`}
          >
            {/* Top row */}
            <div className="flex items-start justify-between">
              <div className="flex flex-col gap-1">
                <div className="flex items-center gap-3">
                  <span className="text-base font-bold text-white">{agent.name}</span>
                  <span
                    className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded ${
                      agent.type === 'local'
                        ? 'bg-surface-800 text-surface-400'
                        : agent.type === 'ide'
                          ? 'bg-surface-800 text-surface-400'
                          : 'bg-surface-800 text-surface-300'
                    }`}
                  >
                    {agent.type}
                  </span>
                </div>
                <span className="text-[11px] font-mono text-surface-500">
                  {agent.model}
                </span>
              </div>

              {/* Enable/disable toggle */}
              <button
                onClick={() => toggleAgent(agent.id)}
                className={`w-10 h-5 rounded-full relative transition-colors ${
                  agent.enabled ? 'bg-white' : 'bg-surface-700'
                }`}
              >
                <div
                  className={`absolute top-0.5 w-4 h-4 rounded-full transition-all ${
                    agent.enabled
                      ? 'left-[22px] bg-black'
                      : 'left-0.5 bg-surface-500'
                  }`}
                />
              </button>
            </div>

            {/* Cost */}
            <div className="flex items-center gap-4">
              <div className="flex flex-col gap-0.5">
                <span className="text-[10px] font-bold text-surface-600 uppercase tracking-wider">
                  Cost
                </span>
                <span className="text-sm font-bold text-white">
                  {agent.costPer1kTokens === 0
                    ? 'Free'
                    : `$${agent.costPer1kTokens.toFixed(3)}/1K tokens`}
                </span>
              </div>
            </div>

            {/* Specialty */}
            <div className="flex flex-col gap-1.5">
              <span className="text-[10px] font-bold text-surface-600 uppercase tracking-wider">
                Specialty
              </span>
              {editingSpecialty === agent.id ? (
                <input
                  type="text"
                  defaultValue={agent.specialty}
                  autoFocus
                  onBlur={(e) => updateSpecialty(agent.id, e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') updateSpecialty(agent.id, e.currentTarget.value)
                    if (e.key === 'Escape') setEditingSpecialty(null)
                  }}
                  className="bg-surface-950 border border-surface-700 rounded-input px-2.5 py-1.5
                    text-xs text-white focus:outline-none focus:border-surface-500"
                />
              ) : (
                <button
                  onClick={() => setEditingSpecialty(agent.id)}
                  className="text-xs text-surface-400 text-left hover:text-white transition-colors"
                >
                  {agent.specialty}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
