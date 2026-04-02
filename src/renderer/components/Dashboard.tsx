import { useCallback, useState } from 'react'
import type { Project } from '@shared/types'
import AgentCard from './AgentCard'
import AgentFeed from './AgentFeed'
import TaskInput from './TaskInput'
import TaskQueue from './TaskQueue'
import AddProjectDialog from './AddProjectDialog'
import { useAgentStore } from '../stores/agentStore'
import { useTaskStore } from '../stores/taskStore'
import { useProjectStore } from '../stores/projectStore'

export default function Dashboard() {
  const agents = useAgentStore((s) => Object.values(s.agents))
  const tasks = useTaskStore((s) => s.tasks)
  const projects = useProjectStore((s) => s.projects)
  const activeProjectId = useProjectStore((s) => s.activeProjectId)
  const addProject = useProjectStore((s) => s.addProject)
  const setActiveProject = useProjectStore((s) => s.setActiveProject)
  const [showAddProject, setShowAddProject] = useState(false)
  const [expandedAgentId, setExpandedAgentId] = useState<string | null>(null)

  const handleSubmitTask = useCallback(async (prompt: string, model: string) => {
    if (!activeProjectId) return
    try {
      await window.api.invoke('task:submit', {
        prompt,
        projectId: activeProjectId,
        model: model === 'auto' ? undefined : model
      })
    } catch (err) {
      console.error('Failed to submit task:', err)
    }
  }, [activeProjectId])

  const handleCancelTask = useCallback(async (id: string) => {
    try {
      await window.api.invoke('task:cancel', id)
    } catch (err) {
      console.error('Failed to cancel task:', err)
    }
  }, [])

  const handleAddProject = useCallback(async (name: string, directory: string, devServerUrl: string) => {
    const project: Project = {
      id: crypto.randomUUID(),
      name,
      directory,
      devServerUrl: devServerUrl || null,
      confidenceThreshold: 85,
      defaultModel: 'anthropic/claude-sonnet-4.6'
    }
    addProject(project)

    // Persist and register with main process
    try {
      await window.api.invoke('project:add', {
        id: project.id,
        name: project.name,
        directory: project.directory,
        devServerUrl: project.devServerUrl
      })
    } catch (err) {
      console.error('Failed to register project:', err)
    }
  }, [addProject])

  // If an agent is expanded, show fullscreen AgentFeed
  if (expandedAgentId) {
    return <AgentFeed agentId={expandedAgentId} onClose={() => setExpandedAgentId(null)} />
  }

  return (
    <div className="h-full flex flex-col px-6 pb-6 overflow-y-auto">
      {/* Task Input */}
      <div className="mb-6">
        <TaskInput
          onSubmit={handleSubmitTask}
          projects={projects}
          activeProjectId={activeProjectId}
          onSelectProject={setActiveProject}
          onAddProject={() => setShowAddProject(true)}
        />
      </div>

      {/* Agent Grid */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-[10px] font-bold text-surface-500 uppercase tracking-[0.2em]">
            Active Agents
          </h2>
          <span className="text-[10px] font-mono text-surface-600">
            {agents.filter((a) => a.status === 'running').length} running
          </span>
        </div>

        {agents.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {agents.map((agent) => (
              <AgentCard
                key={agent.id}
                agent={agent}
                onClick={() => setExpandedAgentId(agent.id)}
              />
            ))}
          </div>
        ) : (
          <div className="bg-surface-900 border border-surface-800 border-dashed rounded-card p-8 text-center">
            <p className="text-sm text-surface-500">
              No active agents. Submit a task to get started.
            </p>
          </div>
        )}
      </div>

      {/* Queue */}
      <TaskQueue tasks={tasks} onCancel={handleCancelTask} />

      {/* Add Project Dialog */}
      <AddProjectDialog
        open={showAddProject}
        onClose={() => setShowAddProject(false)}
        onAdd={handleAddProject}
      />
    </div>
  )
}
