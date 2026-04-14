

# FAVR Remediation Workspace — Parallel Task Breakdown

> **Goal:** After FAVR scans a codebase and produces an optimal patch order, users enter a **Remediation Workspace** where AI agents are dispatched via OpenRouter to fix vulnerabilities. The workspace shows live agent cards, uses statistics to assign the best agent per issue, and optimizes agent selection under a user-defined budget.

> **What exists today:** The `fix:all` IPC handler (`src/main/ipc.ts:466`) already runs agents sequentially using `modelRouter.route()` (cheapest capable model). Agent cards, stores, and streaming infrastructure all work. But there's no dedicated workspace UI, no budget-aware optimization, no agent performance stats, and no parallel dispatch.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   REMEDIATION WORKSPACE (new view)              │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Agent Card   │  │  Agent Card   │  │  Agent Card   │  ...   │
│  │  Claude       │  │  DeepSeek     │  │  Ollama       │        │
│  │  CVE-2024-... │  │  CVE-2023-... │  │  CVE-2024-... │        │
│  │  ████░░ 60%   │  │  ██████ 90%   │  │  ███░░░ 40%   │        │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
│  ┌─ BUDGET BAR ────────────────────────────────────────────┐    │
│  │  Budget: $15.00  |  Spent: $3.40  |  Remaining: $11.60  │    │
│  │  ████████░░░░░░░░░░  23% used                            │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─ PATCH QUEUE ───────────────────────────────────────────┐    │
│  │  1. CVE-2024-1234  [RUNNING]  Claude Sonnet   $0.12     │    │
│  │  2. CVE-2023-5678  [RUNNING]  DeepSeek        $0.002    │    │
│  │  3. CVE-2024-9999  [QUEUED]   Ollama          $0.00     │    │
│  │  ...                                                     │    │
│  └──────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Parallel Work Chunks

Each chunk is **independent** — different people can work on them simultaneously. Interfaces between chunks are defined upfront so nothing blocks.

---

### CHUNK A: Budget-Aware Agent Optimizer (Backend Math)

**Owner:** _______________
**Files to create/modify:**
- `src/main/optimization/budget-optimizer.ts` (NEW)
- `src/main/optimization/router.ts` (MODIFY — extend with budget awareness)
- `src/main/optimization/agent-stats.ts` (NEW)

**What it does:**

Given a list of vulnerabilities (with complexity, severity, type) and a budget cap, produce an optimal assignment of {vulnerability → model} that maximizes expected fix quality while staying under budget.

**Shared interface (other chunks depend on this):**

```typescript
// src/main/optimization/budget-optimizer.ts

export interface AgentStats {
  model: string
  // Historical performance (seeded with defaults, updated over time)
  successRate: number          // 0-1, how often this model produces a successful fix
  avgCostPerFix: number        // average $ per completed fix
  avgTokensPerFix: number      // average tokens consumed
  complexityScores: {          // success rate broken down by complexity
    low: number
    medium: number
    high: number
  }
  taskTypeScores: Record<string, number>  // success rate by vuln type (e.g. "dependency-upgrade", "config-fix")
}

export interface BudgetConstraints {
  maxBudget: number            // total $ cap
  maxConcurrentAgents: number  // how many agents can run at once (default 3)
  preferFree: boolean          // try free models first (default true)
}

export interface AgentAssignment {
  vulnId: string
  cveId: string
  assignedModel: string
  estimatedCost: number
  expectedSuccessRate: number
  reasoning: string            // why this model was chosen
}

export interface OptimizationResult {
  assignments: AgentAssignment[]
  totalEstimatedCost: number
  totalBudget: number
  expectedFixRate: number      // % of vulns expected to be fixed
  skippedVulns: string[]       // vulns that didn't fit in budget
  savingsVsNaive: number       // $ saved compared to using most expensive model for everything
}

export function optimizeAgentAssignments(
  vulns: FavrVulnerability[],
  optimalOrder: string[],
  constraints: BudgetConstraints,
  stats: AgentStats[]
): OptimizationResult
```

**Implementation details:**

1. **Default agent stats** — seed with reasonable defaults for each model:
   - Claude Sonnet: 85% success, ~$0.08/fix, best at high complexity
   - GPT-5.4: 80% success, ~$0.12/fix, good all-around
   - DeepSeek: 70% success, ~$0.003/fix, good for medium/low
   - Gemini Flash: 60% success, ~$0.001/fix, good for low complexity
   - Ollama Llama3: 50% success, $0/fix, decent for low complexity

2. **Optimization algorithm** — greedy knapsack variant:
   - Sort vulns by priority (use existing optimal order from Monte Carlo)
   - For each vuln, pick the model with the best (success_rate / cost) ratio that fits remaining budget
   - If no paid model fits, try free models (Ollama)
   - Track remaining budget as assignments are made

3. **Stats tracking** — after each fix completes, update the model's stats:
   - Store in electron-store under `agentStats` key
   - Success = agent status is `done` AND changed files > 0
   - Update rolling averages

4. **Cost estimation** — use token budget estimates from complexity + model pricing:
   - Pull pricing from `ModelCapability.costPer1kTokens` (already in router.ts)

**Tests to write:** Unit tests for the optimizer with mock vulns/budgets.

---

### CHUNK B: Parallel Agent Dispatch (Backend IPC)

**Owner:** _______________
**Files to create/modify:**
- `src/main/ipc.ts` (MODIFY — new `fix:workspace` handler)
- `src/main/agents/manager.ts` (MODIFY — support concurrent spawns + budget tracking)
- `src/main/agents/workspace-session.ts` (NEW)

**What it does:**

Replace the sequential `fix:all` loop with a workspace session that dispatches agents in parallel (up to `maxConcurrentAgents`), respects budget, and emits richer events for the UI.

**Shared interface (UI depends on this):**

```typescript
// IPC Events — Main → Renderer

'workspace:started': {
  sessionId: string
  assignments: AgentAssignment[]    // from Chunk A
  totalBudget: number
  totalEstimatedCost: number
  maxConcurrent: number
}

'workspace:agentSpawned': {
  sessionId: string
  vulnId: string
  cveId: string
  agentId: string
  model: string
  estimatedCost: number
}

'workspace:agentProgress': {
  sessionId: string
  agentId: string
  progress: number
  line: string                     // latest output line
}

'workspace:agentDone': {
  sessionId: string
  agentId: string
  vulnId: string
  cveId: string
  success: boolean
  actualCost: number
  changedFiles: string[]
  error?: string
}

'workspace:budgetUpdate': {
  sessionId: string
  spent: number
  remaining: number
  totalBudget: number
}

'workspace:complete': {
  sessionId: string
  succeeded: number
  failed: number
  skipped: number
  totalSpent: number
  totalBudget: number
  canUndo: boolean
}

// IPC Events — Renderer → Main

'workspace:start': {
  codebasePath: string
  budget: number
  maxConcurrent: number
  preferFree: boolean
}

'workspace:pause': { sessionId: string }
'workspace:resume': { sessionId: string }
'workspace:cancel': { sessionId: string }
'workspace:retryVuln': { sessionId: string; vulnId: string; model?: string }
```

**Implementation details:**

1. **WorkspaceSession class** (`workspace-session.ts`):
   - Holds session state: assignments, budget tracking, active agents, queue
   - Manages a concurrency pool (run N agents at once, queue the rest)
   - When an agent finishes, pull next from queue and spawn
   - Track actual spend vs estimated spend
   - Support pause/resume/cancel

2. **Concurrency pool:**
   ```
   maxConcurrent = 3 (user-configurable)
   
   [Agent 1: CVE-X] [Agent 2: CVE-Y] [Agent 3: CVE-Z]  ← running
   [CVE-A] [CVE-B] [CVE-C] ...                          ← queued
   
   When Agent 2 finishes → spawn CVE-A into slot 2
   ```

3. **Budget enforcement:**
   - Before spawning each agent, check `spent + estimatedCost <= budget`
   - If over budget, skip and mark as `skipped`
   - Emit `workspace:budgetUpdate` after each agent completes

4. **Git safety:** Keep the existing stash-based undo mechanism from `fix:all`.

---

### CHUNK C: Remediation Workspace UI (Frontend)

**Owner:** _______________
**Files to create/modify:**
- `src/renderer/components/RemediationWorkspace.tsx` (NEW — main view)
- `src/renderer/components/BudgetBar.tsx` (NEW)
- `src/renderer/components/PatchQueue.tsx` (NEW)
- `src/renderer/stores/workspaceStore.ts` (NEW)
- `src/renderer/components/Sidebar.tsx` (MODIFY — add Workspace nav item)
- `src/renderer/components/Dashboard.tsx` (MODIFY — "Fix All" button navigates to workspace)

**What it does:**

A new full-page view that shows the remediation workspace: agent cards grid at top, budget bar in the middle, patch queue at bottom.

**Shared interface (depends on Chunk A types + Chunk B events):**

```typescript
// src/renderer/stores/workspaceStore.ts

interface WorkspaceState {
  sessionId: string | null
  status: 'idle' | 'configuring' | 'running' | 'paused' | 'complete'
  
  // Budget
  totalBudget: number
  spent: number
  
  // Assignments from optimizer
  assignments: AgentAssignment[]
  
  // Live agent tracking
  activeAgents: Map<string, {        // agentId → info
    vulnId: string
    cveId: string
    model: string
    progress: number
    status: 'running' | 'done' | 'error'
    outputLines: string[]
    changedFiles: string[]
    estimatedCost: number
    actualCost: number
  }>
  
  // Results
  completed: { vulnId: string; cveId: string; success: boolean; cost: number }[]
  skipped: string[]
  
  // Config (pre-launch)
  budgetInput: number
  maxConcurrent: number
  preferFree: boolean
}
```

**UI Layout:**

1. **Config panel** (shown before launch):
   - Budget input slider ($0 — $50, default $10)
   - Max concurrent agents slider (1-5, default 3)
   - "Prefer free models" toggle
   - Preview of assignments from optimizer (table: CVE | Model | Est. Cost | Success Rate)
   - "Launch Workspace" button

2. **Active workspace** (shown after launch):
   - **Agent cards grid** — reuse existing `AgentCard.tsx` component, one per active agent
   - **Budget bar** — horizontal progress bar showing spent/remaining, color shifts yellow→red as budget depletes
   - **Patch queue** — scrollable list of all vulns:
     - Green check = done successfully
     - Red X = failed
     - Spinner = running (with agent name)
     - Gray = queued
     - Strikethrough = skipped (over budget)
   - **Controls:** Pause / Resume / Cancel buttons
   - **Summary stats:** vulns fixed, total spent, time elapsed

3. **Completion view:**
   - Summary: X/Y fixed, $Z spent, time taken
   - Undo button (reverts all changes via git stash)
   - Rescan button
   - Per-vuln expandable details (files changed, agent output)

**Wiring:**
- Listen to `workspace:*` IPC events and update `workspaceStore`
- Agent cards get their data from `workspaceStore.activeAgents` mapped into the existing `Agent` type
- "Fix All with Agents" button in Dashboard should navigate to this workspace instead of running inline

---

### CHUNK D: Agent Performance Statistics (Backend + Frontend)

**Owner:** _______________
**Files to create/modify:**
- `src/main/optimization/agent-stats.ts` (NEW — persistence layer, shared with Chunk A)
- `src/renderer/components/tabs/AgentStatsTab.tsx` (NEW — stats visualization)
- `src/renderer/components/RemediationWorkspace.tsx` (MODIFY — show stats in agent cards)

**What it does:**

Track and display per-model performance statistics over time. This data feeds into the budget optimizer (Chunk A) and is also shown in the UI.

**Shared interface:**

```typescript
// src/main/optimization/agent-stats.ts

export interface ModelHistoryEntry {
  timestamp: number
  vulnId: string
  cveId: string
  complexity: 'low' | 'medium' | 'high'
  severity: string
  model: string
  success: boolean
  tokensUsed: number
  cost: number
  durationMs: number
  changedFiles: number
}

export class AgentStatsTracker {
  // Persists to electron-store under 'agentPerformance' key
  
  record(entry: ModelHistoryEntry): void
  getStats(model: string): AgentStats      // aggregated stats for optimizer
  getAllStats(): AgentStats[]               // all models
  getHistory(model: string, limit?: number): ModelHistoryEntry[]
  getLeaderboard(): {                       // models ranked by cost-effectiveness
    model: string
    costEffectiveness: number              // successRate / avgCost (higher = better)
    totalFixes: number
  }[]
  reset(): void
}
```

**Stats to track and display:**

| Stat | How Calculated | Where Shown |
|------|---------------|-------------|
| Success rate | successful fixes / total attempts | Agent card badge, stats tab |
| Avg cost per fix | total spend / successful fixes | Stats tab, optimizer preview |
| Cost effectiveness | success_rate / avg_cost | Leaderboard in stats tab |
| Complexity breakdown | success rate at low/med/high | Stats tab bar chart |
| Speed | avg duration per fix | Stats tab |
| Total fixes | count of successful completions | Agent card, stats tab |

**UI for stats tab:**
- Leaderboard table (model, success rate, avg cost, total fixes, cost effectiveness score)
- Per-model expandable detail with complexity breakdown bar chart
- "Reset stats" button

---

## Dependency Graph Between Chunks

```
CHUNK A (Optimizer)          CHUNK D (Stats)
    │                            │
    │  AgentStats interface      │  AgentStatsTracker class
    │  shared between A & D      │  provides data to A
    └──────────┬─────────────────┘
               │
               ▼
         CHUNK B (Dispatch)
          uses optimizer output
          records stats after each fix
               │
               ▼
         CHUNK C (UI)
          listens to B's events
          shows A's assignments
          displays D's stats
```

**Integration points (do these AFTER individual chunks are done):**

1. B calls `optimizeAgentAssignments()` from A at session start
2. B calls `agentStatsTracker.record()` from D after each agent completes
3. C reads assignments from A's output (passed through B's events)
4. C reads live stats from D for agent card badges

---

## Shared Types File

All chunks should add their types to `src/shared/types.ts` under a new section:

```typescript
// ─── Remediation Workspace Types ─────────────────────────────

export interface AgentAssignment { ... }      // Chunk A
export interface BudgetConstraints { ... }    // Chunk A
export interface OptimizationResult { ... }   // Chunk A
export interface AgentStats { ... }           // Chunk A + D
export interface WorkspaceSession { ... }     // Chunk B
export interface ModelHistoryEntry { ... }    // Chunk D
```

---

## Integration Checklist (after all chunks are done)

- [ ] "Fix All with Agents" button in Dashboard navigates to RemediationWorkspace
- [ ] Workspace config panel calls optimizer and shows preview
- [ ] "Launch" triggers `workspace:start` IPC → B creates session → agents spawn in parallel
- [ ] Agent cards update in real-time via IPC events
- [ ] Budget bar depletes as agents complete
- [ ] Patch queue shows live status per-vuln
- [ ] Stats are recorded after each fix and persist across sessions
- [ ] Pause/Resume/Cancel work
- [ ] Undo reverts all changes
- [ ] Sidebar shows "Workspace" nav item when a session is active

---

## Quick Start per Chunk

**Chunk A person:** Start with `src/main/optimization/router.ts` (read it, understand the existing `ModelRouter`). Build `budget-optimizer.ts` next to it. Export the `optimizeAgentAssignments` function. Write unit tests.

**Chunk B person:** Start with `src/main/ipc.ts:466` (the existing `fix:all` handler) and `src/main/agents/manager.ts`. Build `workspace-session.ts` that wraps the concurrency pool. Wire up new IPC handlers. Keep `fix:all` working as a fallback.

**Chunk C person:** Start with `src/renderer/components/Dashboard.tsx` (understand the current fix-all UI) and `src/renderer/components/AgentCard.tsx`. Build `RemediationWorkspace.tsx` as a new view. Create `workspaceStore.ts`. Wire up IPC listeners.

**Chunk D person:** Start with `src/main/store.ts` (understand electron-store usage). Build `agent-stats.ts` with persistence. Build the stats tab UI. Can stub data for testing before Chunk B integration is ready.
