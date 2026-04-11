// ─── Agent Types ───────────────────────────────────────────────

export type AgentStatus = 'idle' | 'running' | 'validating' | 'error' | 'done'

export type FeedMode = 'terminal' | 'preview' | 'screenshot'

export type PipelineStep = 'queued' | 'coding' | 'writing' | 'executing' | 'validating' | 'approved' | 'rejected' | 'retrying' | 'error'

export interface PipelineEvent {
  step: PipelineStep
  message: string
  timestamp: number
  detail?: string // execution output, confidence score, etc.
}

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
  pipeline: PipelineEvent[] // live pipeline steps
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

// ─── FAVR Analysis Types ──────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export type ComplianceFramework = 'PCI-DSS' | 'SOX' | 'HIPAA' | 'GDPR' | 'SOC2' | 'NIST' | 'ISO27001'

export type AnalysisPhase = 'idle' | 'discovery' | 'docker' | 'dependencies' | 'vulnerabilities' | 'ingest' | 'scan' | 'graph' | 'bayesian' | 'monte-carlo' | 'pareto' | 'blast-radius' | 'scheduling' | 'compliance' | 'complete' | 'error'

export interface FavrMaintenanceWindow {
  day: string
  startTime: string
  endTime: string
  timezone: string
  durationMinutes: number
}

export interface FavrService {
  id: string
  name: string
  techStack: string[]
  tier: 'critical' | 'high' | 'medium' | 'low'
  sla: number
  description: string
  currentRiskScore: number
  complianceFrameworks: ComplianceFramework[]
  maintenanceWindow: FavrMaintenanceWindow | null
}

export interface FavrVulnerability {
  id: string
  cveId: string
  title: string
  description: string
  severity: Severity
  cvssScore: number
  epssScore: number
  exploitProbability: number
  affectedServiceIds: string[]
  affectedPackage: string
  patchedVersion: string
  remediationCost: number
  remediationDowntime: number
  complexity: 'low' | 'medium' | 'high'
  status: 'open' | 'in-progress' | 'patched' | 'verified'
  patchOrder: number | null
  knownExploit: boolean
  complianceViolations: ComplianceFramework[]
  complianceDeadlineDays: number | null
}

export interface FavrDependency {
  from: string
  to: string
  type: 'api' | 'data' | 'auth' | 'shared-lib'
  propagationWeight: number
  description: string
}

export interface FavrSimulationResult {
  optimalOrder: string[]
  naiveOrder: string[]
  optimalCurve: number[]
  naiveCurve: number[]
  totalRiskBefore: number
  totalRiskAfter: number
  riskReduction: number
  iterations: number
  convergenceScore: number
  confidenceIntervals: {
    position: number
    cveId: string
    frequency: number
    alternatives: { cveId: string; frequency: number }[]
  }[]
}

export interface FavrParetoSolution {
  id: string
  patchOrder: string[]
  totalRisk: number
  totalCost: number
  totalDowntime: number
  dominated: boolean
  label?: string
}

export interface FavrBlastRadius {
  vulnId: string
  directServices: string[]
  cascadeServices: string[]
  totalDowntimeMinutes: number
  cascadeRestarts: { serviceId: string; reason: string }[]
}

export interface FavrScheduledPatch {
  vulnId: string
  serviceId: string
  windowDay: string
  windowStart: string
  windowEnd: string
  estimatedStart: number
  estimatedDuration: number
  dependsOn: string[]
  concurrentWith: string[]
  weekNumber: number
}

export interface FavrWhatIfConstraints {
  maxBudgetHours: number | null
  skipServiceIds: string[]
  skipVulnIds: string[]
  maxDowntimeMinutes: number | null
}

export interface FavrWhatIfResult {
  constraints: FavrWhatIfConstraints
  patchableVulns: string[]
  skippedVulns: string[]
  residualRisk: number
  residualRiskByService: Record<string, number>
  totalCost: number
  totalDowntime: number
  complianceGaps: { framework: ComplianceFramework; vulnIds: string[] }[]
}

export interface FavrAnalysisResult {
  graph: {
    services: FavrService[]
    dependencies: FavrDependency[]
    vulnerabilities: FavrVulnerability[]
  }
  riskScores: Record<string, number>
  simulation: FavrSimulationResult
  pareto: {
    solutions: FavrParetoSolution[]
    frontierIds: string[]
  }
  blastRadii: Record<string, FavrBlastRadius>
  schedule: FavrScheduledPatch[]
  complianceSummary: {
    frameworks: ComplianceFramework[]
    violations: { framework: ComplianceFramework; vulnIds: string[]; urgentCount: number }[]
    overallComplianceRisk: number
  }
  timestamp: number
  engineVersion: string
}

export interface FavrAnalysisProgress {
  phase: AnalysisPhase
  progress: number
  message: string
}
