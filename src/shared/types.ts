// ─── Agent Types ───────────────────────────────────────────────

export type AgentStatus = 'idle' | 'running' | 'validating' | 'error' | 'done'

export type FeedMode = 'terminal' | 'preview' | 'screenshot'

export interface Agent {
  id: string
  name: string
  model: string
  status: AgentStatus
  progress: number
  currentTask: string | null
  taskId: string | null
  lastFrame: string | null // base64 screenshot
  outputLines: string[]
  devServerUrl: string | null // live preview URL
  feedMode: FeedMode // what to show in the feed area
  validationScreenshot: string | null // before/after screenshot from validation
}

// ─── Task Types ────────────────────────────────────────────────

export type TaskStatus =
  | 'queued'
  | 'chunking'
  | 'running'
  | 'validating'
  | 'retrying'
  | 'needs_review'
  | 'approved'
  | 'rejected'

export interface Subtask {
  id: string
  parentId: string
  prompt: string
  model: string
  status: TaskStatus
  agentId: string | null
  confidence: number | null
  retryCount: number
  errorContext: ErrorContext | null
}

export interface Task {
  id: string
  prompt: string
  projectId: string
  status: TaskStatus
  model: string | null
  subtasks: Subtask[]
  classification: Classification | null
  confidence: number | null
  cost: number
  createdAt: number
  completedAt: number | null
}

// ─── Classification ────────────────────────────────────────────

export interface Classification {
  type: string
  complexity: 'low' | 'medium' | 'high'
  suggestedModel: string
  reasoning: string
}

// ─── Validation ────────────────────────────────────────────────

export interface ErrorContext {
  screenshot: string | null
  apiResponse: string | null
  testOutput: string | null
  consoleOutput: string | null
  stackTrace: string | null
  diff: string | null
  vlmAnalysis: string | null
}

export interface ValidationResult {
  confidence: number
  reasoning: string
  issues: string[]
  errorContext: ErrorContext
}

// ─── Settings ──────────────────────────────────────────────────

export interface Settings {
  openrouterKey: string
  byokKeys: Record<string, string>
  defaultModel: string
  confidenceThreshold: number
  retryLimit: number
  modelPreferences: Record<string, string> // taskType → model
  soundEnabled: boolean
  pipEnabled: boolean
}

// ─── Project ───────────────────────────────────────────────────

export interface Project {
  id: string
  name: string
  directory: string
  devServerUrl: string | null
  confidenceThreshold: number
  defaultModel: string
}

// ─── IPC ───────────────────────────────────────────────────────

export interface IpcApi {
  invoke: (channel: string, ...args: unknown[]) => Promise<unknown>
  on: (channel: string, callback: (...args: unknown[]) => void) => () => void
}
