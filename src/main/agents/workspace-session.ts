/**
 * Workspace Session — manages a parallel remediation run.
 *
 * Dispatches agents concurrently (up to maxConcurrent), tracks budget spend,
 * records stats, and emits events for the UI. Supports pause/resume/cancel.
 */

import { BrowserWindow } from 'electron'
import { agentManager } from './manager'
import { patchManifest } from './manifest-patcher'
import { agentStatsTracker, type ModelHistoryEntry } from '../optimization/agent-stats'
import type { AgentAssignment } from '../optimization/budget-optimizer'
import type { QueuedSubtask } from '../tasks/queue'
import type { Vulnerability, Service } from '../engine/types'

// Split "pkg@version" on the LAST '@' so scoped npm names like "@types/node@1.2.3"
// parse correctly into name="@types/node", version="1.2.3".
function splitPackageRef(ref: string): { name: string; version: string } {
  if (!ref) return { name: '', version: '' }
  const idx = ref.lastIndexOf('@')
  if (idx <= 0) return { name: ref, version: '' }
  return { name: ref.slice(0, idx), version: ref.slice(idx + 1) }
}

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

    // Main dispatch loop: keep filling slots until queue is empty.
    // Track in-flight spawn promises so we can race them directly and remove
    // entries as they settle — this is the only thing that lets the loop make
    // forward progress past maxConcurrent.
    const inFlight = new Map<string, Promise<void>>()

    while (this.queue.length > 0 || inFlight.size > 0) {
      // Respect pause
      if (this.pausePromise) {
        await this.pausePromise
      }

      // Check cancellation
      if (this.isCancelled()) break

      // Fill available slots
      while (inFlight.size < this.maxConcurrent && this.queue.length > 0) {
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

        // Spawn and track — use the assignment's vulnId as the key since the
        // real agentId is minted inside spawnAgent.
        const key = assignment.vulnId
        const p = this.spawnAgent(assignment).finally(() => { inFlight.delete(key) })
        inFlight.set(key, p)
      }

      // Wait for any in-flight agent to finish before trying to fill slots again.
      if (inFlight.size > 0) {
        await Promise.race(inFlight.values())
      }
    }

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

    // Pre-generate the agentId so the agent manager reuses it. Without this,
    // agentManager.spawn() mints its own UUID and every agent:output event is
    // keyed on an ID the workspace store has never seen — the card stays stuck
    // on "Waiting for output..." even though the agent is actually running.
    const agentId = crypto.randomUUID()

    const subtask: QueuedSubtask = {
      id: agentId,
      parentId: `workspace-${vuln.cveId}`,
      prompt,
      originalPrompt: prompt,
      taskType: 'general',
      complexity: vuln.complexity,
      suggestedModel: null,
      assignedModel: assignment.assignedModel,
      assignedAgentId: agentId,
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

    this.active.set(agentId, {
      assignment,
      startedAt: Date.now()
    })

    this.emit('workspace:agentSpawned', {
      sessionId: this.sessionId,
      vulnId: assignment.vulnId,
      cveId: assignment.cveId,
      agentId,
      model: assignment.assignedModel,
      estimatedCost: assignment.estimatedCost
    })

    const agentStartTime = Date.now()
    let result: WorkspaceAgentResult

    // ─── Tier 1: deterministic manifest patch ───────────────────
    // For pure version bumps (most CVEs) we don't need an LLM at all. Try to
    // bump the version directly in package.json / requirements.txt / etc.
    // If that succeeds, skip the model entirely.
    const { name: pkgName } = splitPackageRef(vuln.affectedPackage)
    const { version: targetVersion } = splitPackageRef(vuln.patchedVersion ?? '')
    if (pkgName && targetVersion) {
      const patch = patchManifest(this.codebasePath, pkgName, targetVersion)
      if (patch.success) {
        this.emit('agent:output', { agentId, line: `> Deterministic patch: bumped ${pkgName} → ${targetVersion}` })
        for (const f of patch.changedFiles) {
          this.emit('agent:output', { agentId, line: `>   modified ${f}` })
        }
        this.emit('agent:status', { agentId, status: 'done', progress: 100 })

        const durationMs = Date.now() - agentStartTime
        result = {
          vulnId: assignment.vulnId,
          cveId: assignment.cveId,
          agentId,
          model: 'deterministic/manifest-patcher',
          success: true,
          actualCost: 0,
          changedFiles: patch.changedFiles,
          durationMs
        }
        await this.recordResult(result, assignment, 0)
        return
      }
    }

    // ─── Tier 2: LLM fallback ───────────────────────────────────
    try {
      await agentManager.spawn(subtask, this.codebasePath)
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
        agentId,
        model: assignment.assignedModel,
        success: false,
        actualCost: 0,
        changedFiles: [],
        durationMs: Date.now() - agentStartTime,
        error: msg
      }
    }

    await this.recordResult(result, assignment, result.actualCost)
  }

  private async recordResult(
    result: WorkspaceAgentResult,
    assignment: AgentAssignment,
    actualCost: number
  ): Promise<void> {
    this.results.push(result)
    this.spent += actualCost

    const statsEntry: ModelHistoryEntry = {
      timestamp: Date.now(),
      vulnId: result.vulnId,
      cveId: result.cveId,
      complexity: assignment.complexity,
      severity: assignment.severity,
      model: result.model,
      success: result.success,
      tokensUsed: 0,
      cost: actualCost,
      durationMs: result.durationMs,
      changedFiles: result.changedFiles.length
    }
    agentStatsTracker.record(statsEntry)

    this.emit('workspace:agentDone', {
      sessionId: this.sessionId,
      agentId: result.agentId,
      vulnId: result.vulnId,
      cveId: result.cveId,
      success: result.success,
      actualCost,
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

    this.active.delete(result.agentId)
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
