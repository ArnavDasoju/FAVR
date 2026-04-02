import { useEffect } from 'react'
import { useAgentStore } from '../stores/agentStore'
import { useTaskStore } from '../stores/taskStore'
import { useSettingsStore } from '../stores/settingsStore'
import { useProjectStore } from '../stores/projectStore'
import { useAuthStore } from '../stores/authStore'
import type { Task, Agent, AgentStatus, PipelineEvent, Project } from '@shared/types'

export function useIpcListeners() {
  // Load persisted settings + projects on mount
  useEffect(() => {
    window.api.invoke('settings:get').then((data: unknown) => {
      const s = data as any
      if (s) {
        useSettingsStore.getState().updateSettings({
          openrouterKey: s.openrouterKey ?? '',
          defaultModel: s.defaultModel ?? 'anthropic/claude-sonnet-4.6',
          confidenceThreshold: s.confidenceThreshold ?? 85,
          retryLimit: s.retryLimit ?? 2,
          modelPreferences: s.modelPreferences ?? {}
        })

        // Restore persisted projects
        if (s.projects?.length > 0) {
          const store = useProjectStore.getState()
          for (const p of s.projects) {
            store.addProject({
              id: p.id,
              name: p.name,
              directory: p.directory,
              devServerUrl: p.devServerUrl ?? null,
              confidenceThreshold: s.confidenceThreshold ?? 85,
              defaultModel: s.defaultModel ?? 'anthropic/claude-sonnet-4.6'
            })
          }
        }
      }
    }).catch(() => {})
  }, [])

  useEffect(() => {
    const unsubs: (() => void)[] = []
    const { addTask, updateTask } = useTaskStore.getState()
    const { addAgent, appendOutput, appendPipeline, setFrame, setStatus } = useAgentStore.getState()

    // Task events from main process
    unsubs.push(
      window.api.on('task:created', (data: unknown) => {
        const task = data as Task
        // Convert queue format to UI format
        addTask({
          id: task.id,
          prompt: task.prompt,
          projectId: task.projectId,
          status: task.status,
          model: task.model ?? null,
          subtasks: task.subtasks ?? [],
          classification: task.classification ?? null,
          confidence: task.confidence ?? null,
          cost: task.cost ?? 0,
          createdAt: task.createdAt ?? Date.now(),
          completedAt: task.completedAt ?? null
        })
      })
    )

    unsubs.push(
      window.api.on('task:updated', (data: unknown) => {
        const task = data as Task
        updateTask(task.id, task)
      })
    )

    // Agent events
    unsubs.push(
      window.api.on('agent:output', (data: unknown) => {
        const { agentId, line } = data as { agentId: string; line: string }
        appendOutput(agentId, line)
      })
    )

    unsubs.push(
      window.api.on('agent:frame', (data: unknown) => {
        const { agentId, frame } = data as { agentId: string; frame: string }
        setFrame(agentId, frame)
      })
    )

    unsubs.push(
      window.api.on('agent:status', (data: unknown) => {
        const { agentId, status, progress, name, model, subtaskId } = data as {
          agentId: string
          status: AgentStatus
          progress: number
          name?: string
          model?: string
          subtaskId?: string
        }

        // If this agent doesn't exist in the store yet, create it
        const existing = useAgentStore.getState().agents[agentId]
        if (!existing) {
          const feedMode = status === 'running' ? 'terminal' : status === 'validating' ? 'preview' : 'screenshot'
          const newAgent: Agent = {
            id: agentId,
            name: name ?? model?.split('/').pop() ?? 'Agent',
            model: model ?? 'unknown',
            status,
            progress,
            currentTask: subtaskId ?? null,
            taskId: subtaskId ?? null,
            lastFrame: null,
            outputLines: [],
            devServerUrl: null,
            feedMode,
            validationScreenshot: null,
            pipeline: []
          }
          addAgent(newAgent)
        } else {
          setStatus(agentId, status, progress)
        }
      })
    )

    unsubs.push(
      window.api.on('agent:validationScreenshot', (data: unknown) => {
        const { agentId, screenshot } = data as { agentId: string; screenshot: string }
        const agent = useAgentStore.getState().agents[agentId]
        if (agent) {
          useAgentStore.getState().updateAgent(agentId, { validationScreenshot: screenshot })
        }
      })
    )

    // Pipeline events — track what stage the agent is in
    unsubs.push(
      window.api.on('agent:pipeline', (data: unknown) => {
        const { agentId, step, message, detail, timestamp } = data as {
          agentId: string | null
          step: string
          message: string
          detail?: string
          timestamp: number
        }
        if (agentId) {
          appendPipeline(agentId, { step: step as any, message, detail, timestamp })
        }
      })
    )

    // Auth change events from main process
    unsubs.push(
      window.api.on('auth:changed', (data: unknown) => {
        const authData = data as { isAuthenticated: boolean; user: any; profile: any }
        useAuthStore.getState().setAuth(authData)
      })
    )

    return () => unsubs.forEach((fn) => fn())
  }, [])
}
