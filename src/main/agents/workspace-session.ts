/**
 * Workspace Session — manages a parallel remediation run.
 *
 * Dispatches agents concurrently (up to maxConcurrent), tracks budget spend,
 * records stats, and emits events for the UI. Supports pause/resume/cancel.
 */

import { BrowserWindow } from 'electron'
import { agentManager } from './manager'
import { agentStatsTracker, type ModelHistoryEntry } from '../optimization/agent-stats'
import type { AgentAssignment } from '../optimization/budget-optimizer'
import type { QueuedSubtask } from '../tasks/queue'
import type { Vulnerability, Service } from '../engine/types'

export type WorkspaceStatus = 'running' | 'paused' | 'complete' | 'cancelled'
// Note: TypeScript needs all values in the union even though 'cancelled' is set
// via the cancel() method — the type is correct as declared above.

export interface WorkspaceAgentResult {
  vulnId: string
  cveId: string
  agentId: string
  model: string
  success: boolean
  actualCost: number
  changedFiles: string[]
  durationMs: number
  error?: string
}

export interface WorkspaceSessionState {
  sessionId: string
  status: WorkspaceStatus
  totalBudget: number
  spent: number
  assignments: AgentAssignment[]
  results: WorkspaceAgentResult[]
  skippedVulns: string[]
  startedAt: number
}

class WorkspaceSession {
  readonly sessionId: string
  private status = 'running' as WorkspaceStatus
  private totalBudget: number
  private spent = 0
  private codebasePath: string
  private maxConcurrent: number

  private assignments: AgentAssignment[]
  private vulnMap: Map<string, Vulnerability>
  private serviceMap: Map<string, Service>
  private skippedVulns: string[]

  // Queue management
  private queue: AgentAssignment[] = []       // waiting to be dispatched
  private active = new Map<string, {           // agentId → assignment info
    assignment: AgentAssignment
    startedAt: number
    resolve: () => void
  }>()
  private results: WorkspaceAgentResult[] = []

  // Pause control
  private pausePromise: Promise<void> | null = null
  private pauseResolve: (() => void) | null = null

  private startedAt: number

  constructor(opts: {
    codebasePath: string
    totalBudget: number
    maxConcurrent: number
    assignments: AgentAssignment[]
    skippedVulns: string[]
    vulns: Vulnerability[]
    services: Service[]
  }) {
    this.sessionId = crypto.randomUUID()
    this.codebasePath = opts.codebasePath
    this.totalBudget = opts.totalBudget
    this.maxConcurrent = opts.maxConcurrent
    this.assignments = opts.assignments
    this.skippedVulns = opts.skippedVulns
    this.vulnMap = new Map(opts.vulns.map(v => [v.id, v]))
    this.serviceMap = new Map(opts.services.map(s => [s.id, s]))
    this.startedAt = Date.now()
  }

  /**
   * Run the full workspace session. Returns when all agents are done or cancelled.
   */
  async run(): Promise<WorkspaceSessionState> {
    // Load the queue in assignment order (which is already optimal order)
    this.queue = [...this.assignments]

    this.emit('workspace:started', {
      sessionId: this.sessionId,
      assignments: this.assignments,
      totalBudget: this.totalBudget,
      totalEstimatedCost: this.assignments.reduce((s, a) => s + a.estimatedCost, 0),
      maxConcurrent: this.maxConcurrent,
      skippedVulns: this.skippedVulns
    })

    // Main dispatch loop: keep filling slots until queue is empty
    const slotPromises: Promise<void>[] = []

    while (this.queue.length > 0 || this.active.size > 0) {
      // Respect pause
      if (this.pausePromise) {
        await this.pausePromise
      }

      // Check cancellation
      if (this.isCancelled()) break

      // Fill available slots
      while (this.active.size < this.maxConcurrent && this.queue.length > 0) {
        if (this.isCancelled()) break

        const assignment = this.queue.shift()!

        // Budget check: skip if estimated cost would exceed remaining budget
        const remaining = this.totalBudget - this.spent
        if (assignment.estimatedCost > remaining && assignment.estimatedCost > 0) {
          this.skippedVulns.push(assignment.vulnId)
          this.emit('workspace:agentSkipped', {
            sessionId: this.sessionId,
            vulnId: assignment.vulnId,
            cveId: assignment.cveId,
            reason: 'over-budget'
          })
          continue
        }

        // Spawn agent in a slot
        const slotP = this.spawnAgent(assignment)
        slotPromises.push(slotP)
      }

      // Wait for any active agent to finish before trying to fill slots again
      if (this.active.size > 0) {
        await Promise.race(Array.from(this.active.values()).map(a => new Promise<void>(r => { a.resolve = r })))
      }
    }

    // Wait for any remaining in-flight agents
    await Promise.allSettled(slotPromises)

    if (this.status !== 'cancelled') {
      this.status = 'complete'
    }

    const state = this.getState()

    this.emit('workspace:complete', {
      sessionId: this.sessionId,
      succeeded: this.results.filter(r => r.success).length,
      failed: this.results.filter(r => !r.success).length,
      skipped: this.skippedVulns.length,
      totalSpent: this.spent,
      totalBudget: this.totalBudget,
      durationMs: Date.now() - this.startedAt
    })

    return state
  }

  /**
   * Spawn a single agent for an assignment. Manages the active slot lifecycle.
   */
  private async spawnAgent(assignment: AgentAssignment): Promise<void> {
    const vuln = this.vulnMap.get(assignment.vulnId)
    if (!vuln) return

    const serviceNames = vuln.affectedServiceIds
      .map(id => this.serviceMap.get(id)?.name)
      .filter((n): n is string => !!n)

    const prompt = buildFixPrompt(vuln, serviceNames)

    const subtask: QueuedSubtask = {
      id: crypto.randomUUID(),
      parentId: `workspace-${vuln.cveId}`,
      prompt,
      originalPrompt: prompt,
      taskType: 'general',
      complexity: vuln.complexity,
      suggestedModel: null,
      assignedModel: assignment.assignedModel,
      assignedAgentId: null,
      status: 'running',
      retryCount: 0,
      maxRetries: 0,
      confidence: null,
      error: null,
      createdAt: Date.now(),
      startedAt: Date.now(),
      completedAt: null,
      gitBranch: null,
      gitOriginalBranch: null,
      gitStashed: false
    }

    // Create a slot entry with a resolver that the dispatch loop awaits
    let slotResolve: () => void
    const slotPromise = new Promise<void>(r => { slotResolve = r })

    // We'll use a temporary agentId until spawn returns the real one
    const tempId = subtask.id

    this.active.set(tempId, {
      assignment,
      startedAt: Date.now(),
      resolve: slotResolve!
    })

    this.emit('workspace:agentSpawned', {
      sessionId: this.sessionId,
      vulnId: assignment.vulnId,
      cveId: assignment.cveId,
      agentId: tempId,
      model: assignment.assignedModel,
      estimatedCost: assignment.estimatedCost
    })

    const agentStartTime = Date.now()
    let result: WorkspaceAgentResult

    try {
      const agentId = await agentManager.spawn(subtask, this.codebasePath)
      const agent = agentManager.getAgent(agentId)
      const success = agent?.status === 'done'
      const changedFiles = agent?.changedFiles ?? []
      const durationMs = Date.now() - agentStartTime

      // Estimate actual cost from token budget (we don't get exact token counts from streaming,
      // so use the estimated cost as a reasonable proxy)
      const actualCost = assignment.estimatedCost

      result = {
        vulnId: assignment.vulnId,
        cveId: assignment.cveId,
        agentId,
        model: assignment.assignedModel,
        success,
        actualCost,
        changedFiles,
        durationMs,
        error: success ? undefined : (agent?.outputLines.slice(-3).join(' ') ?? 'agent failed')
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      result = {
        vulnId: assignment.vulnId,
        cveId: assignment.cveId,
        agentId: tempId,
        model: assignment.assignedModel,
        success: false,
        actualCost: 0,
        changedFiles: [],
        durationMs: Date.now() - agentStartTime,
        error: msg
      }
    }

    // Record result
    this.results.push(result)
    this.spent += result.actualCost

    // Record stats for the optimizer's learning
    const statsEntry: ModelHistoryEntry = {
      timestamp: Date.now(),
      vulnId: result.vulnId,
      cveId: result.cveId,
      complexity: assignment.complexity,
      severity: assignment.severity,
      model: assignment.assignedModel,
      success: result.success,
      tokensUsed: 0, // not available from streaming — stats tracker handles this gracefully
      cost: result.actualCost,
      durationMs: result.durationMs,
      changedFiles: result.changedFiles.length
    }
    agentStatsTracker.record(statsEntry)

    // Emit events
    this.emit('workspace:agentDone', {
      sessionId: this.sessionId,
      agentId: result.agentId,
      vulnId: result.vulnId,
      cveId: result.cveId,
      success: result.success,
      actualCost: result.actualCost,
      changedFiles: result.changedFiles,
      durationMs: result.durationMs,
      error: result.error
    })

    this.emit('workspace:budgetUpdate', {
      sessionId: this.sessionId,
      spent: this.spent,
      remaining: this.totalBudget - this.spent,
      totalBudget: this.totalBudget
    })

    // Free the slot and wake the dispatch loop
    this.active.delete(tempId)
    slotResolve!()
  }

  pause(): void {
    if (this.status !== 'running') return
    this.status = 'paused'
    this.pausePromise = new Promise(r => { this.pauseResolve = r })
    this.emit('workspace:paused', { sessionId: this.sessionId })
  }

  resume(): void {
    if (this.status !== 'paused') return
    this.status = 'running'
    if (this.pauseResolve) {
      this.pauseResolve()
      this.pausePromise = null
      this.pauseResolve = null
    }
    this.emit('workspace:resumed', { sessionId: this.sessionId })
  }

  cancel(): void {
    this.status = 'cancelled'
    // Resume if paused so the loop can exit
    if (this.pauseResolve) {
      this.pauseResolve()
      this.pausePromise = null
      this.pauseResolve = null
    }
    // Kill all active agents
    for (const [agentId] of this.active) {
      agentManager.kill(agentId)
    }
    this.emit('workspace:cancelled', { sessionId: this.sessionId })
  }

  /**
   * Retry a specific vuln with an optionally different model.
   * Pushes it to the front of the queue.
   */
  retryVuln(vulnId: string, model?: string): void {
    const original = this.assignments.find(a => a.vulnId === vulnId)
    if (!original) return

    const retryAssignment: AgentAssignment = {
      ...original,
      assignedModel: model ?? original.assignedModel,
      reasoning: `Retry: ${original.reasoning}`
    }

    // Remove from results if it failed previously
    const failIdx = this.results.findIndex(r => r.vulnId === vulnId)
    if (failIdx >= 0) {
      this.results.splice(failIdx, 1)
    }

    // Push to front of queue
    this.queue.unshift(retryAssignment)

    this.emit('workspace:vulnRetried', {
      sessionId: this.sessionId,
      vulnId,
      model: retryAssignment.assignedModel
    })
  }

  getState(): WorkspaceSessionState {
    return {
      sessionId: this.sessionId,
      status: this.status,
      totalBudget: this.totalBudget,
      spent: this.spent,
      assignments: this.assignments,
      results: this.results,
      skippedVulns: this.skippedVulns,
      startedAt: this.startedAt
    }
  }

  /** Opaque cancellation check — avoids TS control-flow narrowing issues. */
  private isCancelled(): boolean {
    return (this.status as string) === 'cancelled'
  }

  getStatus(): WorkspaceStatus {
    return this.status
  }

  private emit(channel: string, data: unknown) {
    for (const win of BrowserWindow.getAllWindows()) {
      win.webContents.send(channel, data)
    }
  }
}

// ─── Module-level active session tracking ────────────────────

let activeSession: WorkspaceSession | null = null

export function getActiveSession(): WorkspaceSession | null {
  return activeSession
}

export function setActiveSession(session: WorkspaceSession | null): void {
  activeSession = session
}

// ─── Prompt builder (same logic as fix:all, extracted here) ──

function buildFixPrompt(vuln: Vulnerability, serviceNames: string[]): string {
  const [pkgName, currentVersion] = vuln.affectedPackage.split('@')
  const patchedParts = (vuln.patchedVersion ?? '').split('@')
  const targetVersion = patchedParts.length > 1 ? patchedParts.slice(1).join('@') : 'latest safe version'
  const serviceHint = serviceNames.length > 0
    ? ` in service(s): ${serviceNames.join(', ')}`
    : ''

  return `Patch vulnerability ${vuln.cveId} — ${vuln.title}

Package: ${pkgName}
Current version: ${currentVersion ?? 'unknown'}
Target version: ${targetVersion}
Severity: ${vuln.severity} (CVSS ${vuln.cvssScore})${serviceHint}

Details:
${vuln.description}

Your task:
1. Find the dependency manifest (package.json, requirements.txt, go.mod, Cargo.toml, pom.xml, or Gemfile) in this project that depends on "${pkgName}".
2. Update that dependency to version "${targetVersion}".
3. If the upgrade has known breaking changes, also update any calling code in the project that uses the affected package so it matches the new API.
4. Do not touch files unrelated to this vulnerability.

Output every file you modify using this exact format, one block per file:

FILE: <relative/path/to/file>
\`\`\`
<full updated file contents>
\`\`\`
`
}

export { WorkspaceSession }
