/**
 * Task Queue — manages task lifecycle, priority, and agent assignment.
 *
 * Wires together: chunker → agent manager → validation → retry loop.
 */

import { BrowserWindow } from 'electron'
import { chunkTask, type ChunkedSubtask } from './chunker'
import { runValidation, type ValidatorConfig } from '../validation/validator'
import { modelRouter } from '../optimization/router'
import { prepareBranch, commitAgentChanges, mergeBranch, rejectBranch } from '../git/safety'

export type QueuedTaskStatus = 'queued' | 'chunking' | 'running' | 'validating' | 'retrying' | 'needs_review' | 'approved' | 'rejected'

export interface QueuedSubtask {
  id: string
  parentId: string
  prompt: string
  originalPrompt: string // preserved for retries (prompt gets replaced with error context)
  taskType: string
  complexity: 'low' | 'medium' | 'high'
  suggestedModel: string | null
  assignedModel: string | null
  assignedAgentId: string | null
  status: QueuedTaskStatus
  retryCount: number
  maxRetries: number
  confidence: number | null
  error: string | null
  createdAt: number
  startedAt: number | null
  completedAt: number | null
  // Git safety
  gitBranch: string | null
  gitOriginalBranch: string | null
  gitStashed: boolean
}

export interface QueuedTask {
  id: string
  prompt: string
  projectId: string
  requestedModel: string | null // user's choice, null = auto
  status: QueuedTaskStatus
  subtasks: QueuedSubtask[]
  totalCost: number
  createdAt: number
  completedAt: number | null
}

// Agent spawner function — set by main process to avoid circular imports
type AgentSpawner = (subtask: QueuedSubtask, projectDir: string) => Promise<{ agentId: string; output: string[] }>

class TaskQueue {
  private tasks: Map<string, QueuedTask> = new Map()
  private projectDirs: Map<string, string> = new Map() // projectId → directory
  private devServerUrls: Map<string, string> = new Map() // projectId → URL
  private modelPreferences: Record<string, string> = {} // taskType → model
  private confidenceThreshold = 85
  private maxRetries = 2
  private spawnAgent: AgentSpawner | null = null
  private geminiApiKey: string | null = null
  private processing = false

  setModelPreferences(prefs: Record<string, string>) {
    this.modelPreferences = prefs
  }

  setConfidenceThreshold(threshold: number) {
    this.confidenceThreshold = threshold
  }

  setMaxRetries(max: number) {
    this.maxRetries = max
  }

  setAgentSpawner(fn: AgentSpawner) {
    this.spawnAgent = fn
  }

  setGeminiApiKey(key: string) {
    this.geminiApiKey = key
  }

  setProjectDir(projectId: string, dir: string) {
    this.projectDirs.set(projectId, dir)
  }

  setDevServerUrl(projectId: string, url: string) {
    this.devServerUrls.set(projectId, url)
  }

  /** @deprecated Use setAgentSpawner instead */
  setAgentAssigner(_fn: unknown) {
    // Back-compat stub — the new flow uses setAgentSpawner
  }

  /**
   * Submit a new task — chunks it and adds subtasks to the queue.
   */
  async submit(prompt: string, projectId: string, requestedModel: string | null): Promise<QueuedTask> {
    const taskId = crypto.randomUUID()

    const task: QueuedTask = {
      id: taskId,
      prompt,
      projectId,
      requestedModel,
      status: 'chunking',
      subtasks: [],
      totalCost: 0,
      createdAt: Date.now(),
      completedAt: null
    }

    this.tasks.set(taskId, task)
    this.emit('task:created', task)

    // Chunk the task
    const chunks = await chunkTask(prompt)
    task.subtasks = chunks.map((chunk) => this.createSubtask(taskId, chunk, requestedModel))
    task.status = 'queued'
    this.emit('task:updated', task)

    // Start processing
    this.processNext()

    return task
  }

  private createSubtask(parentId: string, chunk: ChunkedSubtask, requestedModel: string | null): QueuedSubtask {
    // Priority: user's explicit model choice > user's model preferences per type > router (free-first)
    const assignedModel =
      requestedModel ??
      this.modelPreferences[chunk.taskType] ??
      modelRouter.route(chunk.taskType, chunk.complexity)

    return {
      id: crypto.randomUUID(),
      parentId,
      prompt: chunk.prompt,
      originalPrompt: chunk.prompt,
      taskType: chunk.taskType,
      complexity: chunk.complexity,
      suggestedModel: chunk.suggestedModel,
      assignedModel,
      assignedAgentId: null,
      status: 'queued',
      retryCount: 0,
      maxRetries: this.maxRetries,
      confidence: null,
      error: null,
      createdAt: Date.now(),
      startedAt: null,
      completedAt: null,
      gitBranch: null,
      gitOriginalBranch: null,
      gitStashed: false
    }
  }

  /**
   * Process next queued subtask. Runs the full loop:
   * spawn agent → validate → confidence route → retry or done.
   */
  processNext() {
    if (this.processing) return
    this.processing = true

    // Find next queued subtask
    for (const task of this.tasks.values()) {
      for (const subtask of task.subtasks) {
        if (subtask.status === 'queued') {
          this.executeSubtask(task, subtask).finally(() => {
            this.processing = false
            this.processNext()
          })
          return
        }
      }
    }

    this.processing = false
  }

  /**
   * Full execution pipeline for a single subtask.
   */
  private async executeSubtask(task: QueuedTask, subtask: QueuedSubtask): Promise<void> {
    const projectDir = this.projectDirs.get(task.projectId)
    if (!projectDir) {
      subtask.status = 'needs_review'
      subtask.error = 'No project directory configured'
      this.emit('task:updated', task)
      return
    }

    // Mark running
    subtask.status = 'running'
    subtask.startedAt = Date.now()
    task.status = 'running'
    this.emit('task:updated', task)

    // Git safety: create branch on first run (not on retries — reuse same branch)
    if (!subtask.gitBranch) {
      const branchResult = prepareBranch(projectDir, subtask.id)
      if (branchResult) {
        subtask.gitBranch = branchResult.branch
        subtask.gitOriginalBranch = branchResult.originalBranch
        subtask.gitStashed = branchResult.stashed
      }
      // If git isn't available, we proceed without branch safety
    }

    // Spawn agent
    if (!this.spawnAgent) {
      subtask.status = 'needs_review'
      subtask.error = 'No agent spawner configured'
      this.emit('task:updated', task)
      return
    }

    let agentOutput: string[] = []
    try {
      const result = await this.spawnAgent(subtask, projectDir)
      subtask.assignedAgentId = result.agentId
      agentOutput = result.output
    } catch (err) {
      subtask.status = 'needs_review'
      subtask.error = err instanceof Error ? err.message : String(err)
      this.updateParentStatus(task)
      this.emit('task:updated', task)
      return
    }

    // Commit agent changes before validation
    if (subtask.gitBranch) {
      commitAgentChanges(projectDir, subtask.id, subtask.originalPrompt)
    }

    // Validate
    subtask.status = 'validating'
    task.status = 'validating'
    this.emit('task:updated', task)

    const devServerUrl = this.devServerUrls.get(task.projectId) ?? null
    const validatorConfig: ValidatorConfig = {
      geminiApiKey: this.geminiApiKey,
      confidenceThreshold: this.confidenceThreshold
    }

    const validation = await runValidation({
      subtask,
      projectDir,
      devServerUrl,
      agentOutput,
      config: validatorConfig
    })

    subtask.confidence = validation.confidence

    // Confidence routing
    if (validation.confidence >= this.confidenceThreshold) {
      // Auto-approve
      subtask.status = 'approved'
      subtask.completedAt = Date.now()
      subtask.error = null
    } else if (validation.confidence < 5) {
      // Too broken — skip retries, ask human
      subtask.status = 'needs_review'
      subtask.error = validation.reasoning
    } else if (subtask.retryCount < subtask.maxRetries) {
      // Retry with descriptive error prompt
      subtask.retryCount++
      subtask.error = validation.reasoning

      if (validation.errorPrompt) {
        // Modify the prompt to include error context for the retry
        subtask.prompt = validation.errorPrompt
      }

      subtask.status = 'queued' // re-queue for retry
    } else {
      // Retries exhausted
      subtask.status = 'needs_review'
      subtask.error = validation.reasoning
    }

    this.updateParentStatus(task)
    this.emit('task:updated', task)
  }

  /**
   * Manual approve/reject from user.
   */
  approve(taskId: string) {
    const task = this.tasks.get(taskId)
    if (!task) return

    const projectDir = this.projectDirs.get(task.projectId)

    for (const subtask of task.subtasks) {
      if (subtask.status === 'needs_review') {
        subtask.status = 'approved'
        subtask.completedAt = Date.now()

        // Merge git branch on approval
        if (subtask.gitBranch && subtask.gitOriginalBranch && projectDir) {
          const result = mergeBranch(projectDir, subtask.gitBranch, subtask.gitOriginalBranch, subtask.gitStashed)
          if (!result.success) {
            console.error('[queue] merge failed:', result.error)
          }
        }
      }
    }
    this.updateParentStatus(task)
    this.emit('task:updated', task)
  }

  reject(taskId: string) {
    const task = this.tasks.get(taskId)
    if (!task) return

    const projectDir = this.projectDirs.get(task.projectId)

    for (const subtask of task.subtasks) {
      if (subtask.status !== 'approved') {
        subtask.status = 'rejected'
        subtask.completedAt = Date.now()

        // Delete git branch on rejection (discards agent changes)
        if (subtask.gitBranch && subtask.gitOriginalBranch && projectDir) {
          const result = rejectBranch(projectDir, subtask.gitBranch, subtask.gitOriginalBranch, subtask.gitStashed)
          if (!result.success) {
            console.error('[queue] branch cleanup failed:', result.error)
          }
        }
      }
    }
    task.status = 'rejected'
    task.completedAt = Date.now()
    this.emit('task:updated', task)
  }

  cancel(taskId: string) {
    this.tasks.delete(taskId)
  }

  getTask(taskId: string): QueuedTask | undefined {
    return this.tasks.get(taskId)
  }

  getAllTasks(): QueuedTask[] {
    return Array.from(this.tasks.values())
  }

  private updateParentStatus(task: QueuedTask) {
    const allDone = task.subtasks.every((s) => s.status === 'approved' || s.status === 'rejected')
    const anyNeedsReview = task.subtasks.some((s) => s.status === 'needs_review')
    const anyRunning = task.subtasks.some((s) => s.status === 'running' || s.status === 'queued' || s.status === 'retrying')

    if (allDone) {
      const anyRejected = task.subtasks.some((s) => s.status === 'rejected')
      task.status = anyRejected ? 'rejected' : 'approved'
      task.completedAt = Date.now()
    } else if (anyNeedsReview) {
      task.status = 'needs_review'
    } else if (anyRunning) {
      task.status = 'running'
    }
  }

  private findSubtask(subtaskId: string): { task: QueuedTask | null; subtask: QueuedSubtask | null } {
    for (const task of this.tasks.values()) {
      const subtask = task.subtasks.find((s) => s.id === subtaskId)
      if (subtask) return { task, subtask }
    }
    return { task: null, subtask: null }
  }

  private emit(channel: string, data: unknown) {
    const wins = BrowserWindow.getAllWindows()
    for (const win of wins) {
      win.webContents.send(channel, data)
    }
  }
}

// Singleton
export const taskQueue = new TaskQueue()
