/**
 * Task Queue — manages task lifecycle, priority, and agent assignment.
 *
 * Wires together: chunker → agent manager → validation → retry loop.
 */

import { BrowserWindow } from 'electron'
import { chunkTask, type ChunkedSubtask } from './chunker'
import { runValidation, type ValidatorConfig } from '../validation/validator'
import { modelRouter } from '../optimization/router'
import { prepareBranch, commitAgentChanges, mergeBranch, rejectBranch, isGitRepo } from '../git/safety'
import { feedStreamer } from '../feeds/streamer'
import { cloudClient } from '../cloud/supabase'

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
type AgentSpawner = (subtask: QueuedSubtask, projectDir: string) => Promise<{ agentId: string; output: string[]; changedFiles: string[] }>

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

    // Chunk the task — Pro users get LLM classification via cloud, BYOK users get heuristic
    const isProCloud = cloudClient.isAuthenticated && cloudClient.isProUser
    const classifyFn = isProCloud
      ? async (input: string) => {
          const result = await cloudClient.classify(input) as any
          return {
            subtasks: (result.subtasks ?? []).map((s: any) => ({
              prompt: s.prompt,
              suggestedModel: s.suggested_model ?? null,
              taskType: s.type ?? 'general',
              complexity: s.complexity ?? 'medium'
            }))
          }
        }
      : undefined

    const chunks = await chunkTask(prompt, { classifyFn })
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
    if (!subtask.gitBranch && isGitRepo(projectDir)) {
      const branchResult = prepareBranch(projectDir, subtask.id)
      if (branchResult) {
        subtask.gitBranch = branchResult.branch
        subtask.gitOriginalBranch = branchResult.originalBranch
        subtask.gitStashed = branchResult.stashed
      }
    }

    // Spawn agent
    if (!this.spawnAgent) {
      subtask.status = 'needs_review'
      subtask.error = 'No agent spawner configured'
      this.emit('task:updated', task)
      return
    }

    let agentOutput: string[] = []
    let changedFiles: string[] = []
    try {
      const result = await this.spawnAgent(subtask, projectDir)
      subtask.assignedAgentId = result.agentId
      agentOutput = result.output
      changedFiles = result.changedFiles ?? []

      // Pipeline: coding complete
      this.emitPipeline(result.agentId, 'coding', `Generated code with ${subtask.assignedModel ?? 'auto'}`)

      // Pipeline: writing files
      if (changedFiles.length > 0) {
        this.emitPipeline(result.agentId, 'writing', `Wrote ${changedFiles.length} file(s): ${changedFiles.join(', ')}`)
      } else {
        this.emitPipeline(result.agentId, 'writing', 'No file changes detected in output')
      }
    } catch (err) {
      subtask.status = 'needs_review'
      subtask.error = err instanceof Error ? err.message : String(err)
      this.emitPipeline(subtask.assignedAgentId, 'error', subtask.error)
      this.updateParentStatus(task)
      this.emit('task:updated', task)
      return
    }

    // Commit agent changes before validation
    if (subtask.gitBranch && isGitRepo(projectDir)) {
      commitAgentChanges(projectDir, subtask.id, subtask.originalPrompt)
    }

    // Pipeline: executing (will be updated with result after validation)
    this.emitPipeline(subtask.assignedAgentId, 'executing', 'Running code to verify it works...')

    // Validate
    subtask.status = 'validating'
    task.status = 'validating'
    this.emit('task:updated', task)

    const devServerUrl = this.devServerUrls.get(task.projectId) ?? null

    // Start live feed streaming during validation (if dev server available)
    if (devServerUrl && subtask.assignedAgentId) {
      feedStreamer.startStreaming(subtask.assignedAgentId, devServerUrl)
    }

    // Pro users validate through cloud edge function (free, uses BLD's Gemini key)
    // BYOK users validate locally (needs their own Gemini key, or falls back to heuristic)
    const isProCloud = cloudClient.isAuthenticated && cloudClient.isProUser

    let validation: { confidence: number; reasoning: string; issues: string[]; errorPrompt?: string }

    if (isProCloud) {
      const cloudResult = await cloudClient.validate({
        prompt: subtask.originalPrompt,
        diff: undefined, // TODO: pass git diff once available
        agent_output: agentOutput.join('\n')
      }) as any

      validation = {
        confidence: cloudResult.confidence ?? 50,
        reasoning: cloudResult.reasoning ?? 'Cloud validation',
        issues: cloudResult.issues ?? [],
        errorPrompt: cloudResult.suggestion
          ? `You were asked to: ${subtask.originalPrompt}\n\nValidation found issues:\n${cloudResult.reasoning}\n\nSuggestion: ${cloudResult.suggestion}\n\nFix these issues.`
          : undefined
      }
    } else {
      const validatorConfig: ValidatorConfig = {
        geminiApiKey: this.geminiApiKey,
        confidenceThreshold: this.confidenceThreshold
      }

      const localResult = await runValidation({
        subtask,
        projectDir,
        devServerUrl,
        agentOutput,
        changedFiles,
        config: validatorConfig
      })

      validation = {
        confidence: localResult.confidence,
        reasoning: localResult.reasoning,
        issues: localResult.issues,
        errorPrompt: localResult.errorPrompt ?? undefined
      }

      // Pipeline: show execution output with verification
      if (localResult.executionCommand) {
        const statusIcon = localResult.executionSuccess ? 'Passed' : 'Failed'

        // Build detail that shows expected vs actual
        const lines: string[] = []
        if (localResult.executionOutput) {
          lines.push(`Output: ${localResult.executionOutput}`)
        }
        // Show the verification reasoning from the executor
        if (localResult.executionReasoning) {
          lines.push(localResult.executionReasoning)
        }

        this.emitPipeline(
          subtask.assignedAgentId,
          'executing',
          `${statusIcon} — \`${localResult.executionCommand}\``,
          lines.join('\n') || '(no output)'
        )
      }
    }

    // Stop live feed, capture final frame
    if (subtask.assignedAgentId) {
      feedStreamer.stopStreaming(subtask.assignedAgentId)
      if (devServerUrl) {
        await feedStreamer.captureFinalFrame(subtask.assignedAgentId, devServerUrl)
      }
    }

    subtask.confidence = validation.confidence

    // Pipeline: validation complete
    this.emitPipeline(subtask.assignedAgentId, 'validating', `Confidence: ${validation.confidence}% — ${truncate(validation.reasoning, 200)}`)

    // Confidence routing
    if (validation.confidence >= this.confidenceThreshold) {
      // Auto-approve
      subtask.status = 'approved'
      subtask.completedAt = Date.now()
      subtask.error = null
      this.emitPipeline(subtask.assignedAgentId, 'approved', `Auto-approved with ${validation.confidence}% confidence`)
    } else if (validation.confidence < 5) {
      // Too broken — skip retries, ask human
      subtask.status = 'needs_review'
      subtask.error = validation.reasoning
      this.emitPipeline(subtask.assignedAgentId, 'error', `Needs review — ${truncate(validation.reasoning, 200)}`)
    } else if (subtask.retryCount < subtask.maxRetries) {
      // Retry with descriptive error prompt
      subtask.retryCount++
      subtask.error = validation.reasoning
      this.emitPipeline(subtask.assignedAgentId, 'retrying', `Retry ${subtask.retryCount}/${subtask.maxRetries} — ${truncate(validation.reasoning, 150)}`)

      if (validation.errorPrompt) {
        subtask.prompt = validation.errorPrompt
      }

      subtask.status = 'queued' // re-queue for retry
    } else {
      // Retries exhausted
      subtask.status = 'needs_review'
      subtask.error = validation.reasoning
      this.emitPipeline(subtask.assignedAgentId, 'rejected', `Retries exhausted — needs human review`)
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

  private emitPipeline(agentId: string | null, step: string, message: string, detail?: string) {
    this.emit('agent:pipeline', {
      agentId,
      step,
      message,
      detail,
      timestamp: Date.now()
    })
  }

  private emit(channel: string, data: unknown) {
    const wins = BrowserWindow.getAllWindows()
    for (const win of wins) {
      win.webContents.send(channel, data)
    }
  }
}

/** Truncate text to maxLen, ending at a word boundary with "..." */
function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text
  const cut = text.slice(0, maxLen)
  const lastSpace = cut.lastIndexOf(' ')
  return (lastSpace > maxLen * 0.5 ? cut.slice(0, lastSpace) : cut) + '...'
}

// Singleton
export const taskQueue = new TaskQueue()
