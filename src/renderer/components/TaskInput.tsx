import { useState } from 'react'
import type { Project } from '@shared/types'

interface TaskInputProps {
  onSubmit: (prompt: string, model: string) => void
  projects: Project[]
  activeProjectId: string | null
  onSelectProject: (id: string) => void
  onAddProject: () => void
}

const models = [
  { value: 'auto', label: 'Auto' },
  { value: 'anthropic/claude-sonnet-4.6', label: 'Claude Sonnet' },
  { value: 'openai/gpt-5.4', label: 'GPT-5.4' },
  { value: 'ollama/llama3', label: 'Ollama' }
]

export default function TaskInput({
  onSubmit,
  projects,
  activeProjectId,
  onSelectProject,
  onAddProject
}: TaskInputProps) {
  const [prompt, setPrompt] = useState('')
  const [model, setModel] = useState('auto')

  const activeProject = projects.find((p) => p.id === activeProjectId)

  const handleSubmit = () => {
    if (!prompt.trim()) return
    if (!activeProjectId) return
    onSubmit(prompt.trim(), model)
    setPrompt('')
  }

  return (
    <div className="bg-surface-900 border border-surface-800 rounded-card p-4 flex flex-col gap-3">
      {/* Input row */}
      <div className="flex items-center gap-3">
        <input
          type="text"
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder={activeProject ? `What do you want to build in ${activeProject.name}?` : 'Select a project first...'}
          disabled={!activeProjectId}
          className="flex-1 bg-surface-950 border border-surface-800 rounded-input px-4 py-3
            text-sm text-white placeholder:text-surface-600
            focus:outline-none focus:border-surface-500 transition-colors
            disabled:opacity-40 disabled:cursor-not-allowed"
        />
        <button
          onClick={handleSubmit}
          disabled={!prompt.trim() || !activeProjectId}
          className="px-6 py-3 bg-white text-black text-sm font-bold rounded-btn
            hover:bg-surface-200 transition-colors
            disabled:opacity-20 disabled:cursor-not-allowed uppercase tracking-wide shrink-0"
        >
          Send
        </button>
      </div>

      {/* Controls row */}
      <div className="flex items-center gap-4">
        {/* Project selector */}
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider shrink-0">
            Project
          </span>
          {projects.length > 0 ? (
            <select
              value={activeProjectId ?? ''}
              onChange={(e) => onSelectProject(e.target.value)}
              className="bg-surface-950 border border-surface-800 rounded-input px-2.5 py-1.5
                text-xs text-surface-300 focus:outline-none focus:border-surface-500
                cursor-pointer max-w-[200px]"
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          ) : (
            <button
              onClick={onAddProject}
              className="bg-surface-950 border border-surface-800 border-dashed rounded-input px-3 py-1.5
                text-xs text-surface-500 hover:text-white hover:border-surface-500 transition-colors"
            >
              + Add Project
            </button>
          )}
          {projects.length > 0 && (
            <button
              onClick={onAddProject}
              className="text-surface-600 hover:text-white transition-colors text-xs font-bold"
              title="Add project"
            >
              +
            </button>
          )}
        </div>

        {/* Divider */}
        <div className="w-px h-4 bg-surface-800" />

        {/* Model selector */}
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-bold text-surface-500 uppercase tracking-wider shrink-0">
            Model
          </span>
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="bg-surface-950 border border-surface-800 rounded-input px-2.5 py-1.5
              text-xs text-surface-300 focus:outline-none focus:border-surface-500
              cursor-pointer"
          >
            {models.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </div>

        {/* Active project path */}
        {activeProject && (
          <>
            <div className="w-px h-4 bg-surface-800" />
            <span className="text-[10px] font-mono text-surface-600 truncate">
              {activeProject.directory}
            </span>
          </>
        )}
      </div>
    </div>
  )
}
