# BLD Build Spec

## Overview

BLD is mission control for AI coding agents. A **workspace** where you manage a roster of AI agents like a portfolio — assign them to flows, set budgets, and optimize allocation across tasks. Think portfolio optimization but for AI workers.

**Not an IDE.** Users keep their existing IDE open. BLD is a companion that dispatches tasks, shows live agent activity, validates results, and pings your phone when needed.

## The Pitch

> "See all your AI agents working in real-time. Get pinged when they need you. Approve from your phone."

---

## Workspace Concept

BLD is structured as a **workspace** with these core abstractions:

### Agent Roster ("Who do you want working today?")

Users build a roster of agents, each with different capabilities and cost profiles. Like hiring a team:

| Agent | Type | Cost | Best For |
|-------|------|------|----------|
| Claude Sonnet | Cloud (OpenRouter) | ~$3/1M tokens | Complex logic, architecture |
| GPT-5.4 | Cloud (OpenRouter) | ~$5/1M tokens | Broad tasks, refactoring |
| Ollama Llama3 | Local | Free | Simple tasks, indexing, privacy |
| Cursor | IDE Agent (Listener) | BYOK | CSS, UI changes, file edits |

Users can:
- **Add/remove agents** from their roster
- **Set agent specialties** — "Cursor handles CSS", "Claude handles auth logic"
- **Enable/disable agents** per session — "Today I only want Claude and Ollama"

### Flows (Workstreams)

A **flow** is a workstream — a sequence of tasks targeting a feature or goal. Flows can run in parallel.

```
Flow: "Add Authentication"
  ├── Subtask 1: Design auth schema     → Claude (logic)
  ├── Subtask 2: Implement login UI     → Cursor (CSS/UI)
  ├── Subtask 3: Write auth middleware   → Claude (logic)
  └── Subtask 4: Integration tests      → GPT-5.4 (testing)

Flow: "Optimize Performance"
  ├── Subtask 1: Profile slow queries   → Claude (analysis)
  └── Subtask 2: Add caching layer      → Claude (logic)
```

Users can:
- **Create flows** from a single prompt (auto-chunked into subtasks)
- **Assign agents to subtasks** manually or let the classifier auto-assign
- **Reorder/reprioritize** flows and subtasks
- **Run multiple flows** in parallel (multiple agents working simultaneously)

### Budget & Cost Optimization

Like portfolio optimization — maximize task completion quality within a budget constraint.

```
┌─ BUDGET ─────────────────────────────────────────┐
│ Monthly budget: $50.00                           │
│ Spent this month: $23.40                         │
│ Remaining: $26.60                                │
│ ████████████░░░░░░░░░ 47% used                   │
│                                                  │
│ Burn rate: ~$3.20/day                            │
│ Projected: $38.40 by month end (under budget)    │
└──────────────────────────────────────────────────┘
```

Budget features:
- **Set monthly/weekly budget cap** — system warns or pauses when approaching limit
- **Cost-per-task estimates** — before executing, show estimated cost based on model + complexity
- **Smart allocation** — auto-suggest cheapest capable agent for each subtask
- **Spend breakdown** — by agent, by flow, by task type
- **Budget alerts** — "You've used 80% of your monthly budget"
- **Free-first routing** — always try Ollama/local models first if capable, fall back to paid only when needed

---

## Business Model

### Model 1: Credits (Pro)

All providers accessed through **one API** (OpenRouter): Anthropic, OpenAI, Google, xAI, Mistral, Deepseek, Cohere, Meta, Qwen, Kimi. Local models (Ollama) are always free.

| Tier | Price | What They Get |
|------|-------|---------------|
| **Free** | $0 | Ollama only, dashboard, no mobile |
| **Pro** | $20/mo + credits | All features, buy credits in-app, $5 in free monthly credits |
| **Team** | $15/user/mo | Shared dashboard + credit model |

**Credit Economics (example: user buys $50 in credits):**

| Step | Amount | Notes |
|------|--------|-------|
| User pays | $50.00 | |
| Stripe fee (2.9%) | -$1.45 | Payment processing |
| **Our cut (22.5%)** | **-$10.92** | BLD revenue |
| OpenRouter fee (5.5%) | -$2.08 | API routing |
| Credits for user | **$35.57** | Actual model spend |

We classify tasks and assign different agents from the models we offer. Users can select from models we pick.

### Model 2: BYOK (Bring Your Own Keys)

- $15/mo subscription
- User brings their own API keys for any provider
- Uses "Employ" model — "Who do you want working today?"
- Same agent features, user pays providers directly

**Economics:** Classification and validation are always free (Gemini Flash). Revenue comes from subscriptions + credit markup (Model 1).

---

## Token Optimization Engine

BLD aggressively reduces token usage to stretch user credits further. This is a core competitive advantage — users get more done per dollar.

### 1. Prompt Caching (biggest win, ~90% savings on cached portion)

Cache static context (system prompt + project structure + file contents) so repeated agent calls don't re-send it. Anthropic supports `cache_control` headers, OpenAI has similar. OpenRouter passes these through.

```
First call:  [system: 4000 tokens] [project context: 8000 tokens] [task: 200 tokens]
             └── cached ──────────────────────────────────────────┘
Second call: [cache hit: ~0 tokens] [task: 200 tokens]
             90% cheaper for the cached portion
```

**Implementation:** When an agent starts a flow, build a "project snapshot" (file tree, key file contents, configs) and pin it as a cached system message. All subtask calls within that flow reuse the cache.

### 2. Smart Context Windowing

Don't dump the whole codebase. Only send files relevant to the current subtask.

**Implementation:**
- Classifier identifies which files/directories are relevant to each subtask
- File dependency graph: if editing `auth.ts`, include its imports but not unrelated files
- Start minimal (just the target file + its direct imports), let the agent request more if needed

```
BAD:  "Here are all 200 files in your project" (50K tokens)
GOOD: "Here are the 4 files relevant to this auth fix" (3K tokens)
```

### 3. Diff-Based Updates

After the first full file read, only send diffs between turns — not the whole file again.

**Implementation:**
- Track which files the agent has seen in the current session
- On subsequent turns, send only the changed lines (unified diff format)
- Agent reconstructs full file from its cached version + diff

### 4. Conversation Compression

Long agent sessions accumulate huge message histories. Periodically summarize older turns.

**Implementation:**
- After every N turns (e.g., 10), compress older messages into a summary
- Use a cheap model (Gemini Flash, free) to generate the summary
- Replace old messages with: `[Summary of turns 1-10: Implemented auth schema, fixed 2 type errors, added session middleware]`
- Keep recent 3-5 turns in full detail

```
Before: 45 messages, 32K tokens of history
After:  1 summary (500 tokens) + 5 recent messages (3K tokens) = 3.5K tokens
```

### 5. Token Budgets Per Task

Set max output tokens based on task complexity to prevent over-generation.

| Complexity | Max Output Tokens | Example |
|-----------|-------------------|---------|
| Low | 1,000 | Fix a typo, change a color |
| Medium | 4,000 | Add a component, write a function |
| High | 8,000 | Architect a feature, refactor a module |

**Implementation:** Classifier assigns complexity → maps to token budget → passed as `max_tokens` to the API call.

### 6. Free-First Routing

Always try the cheapest capable option first.

```
Task comes in
  ├── Can Ollama handle it? (free) → Use Ollama
  ├── Can Gemini Flash handle it? (free) → Use Gemini
  ├── Can DeepSeek handle it? (cheap) → Use DeepSeek
  └── Needs Claude/GPT? (expensive) → Use them
```

### Token Savings Dashboard

Show users exactly how much BLD is saving them in the Budget view:

```
┌─ TOKEN SAVINGS ──────────────────────────────┐
│ Prompt caching saved:      $12.40 (68%)      │
│ Context windowing saved:   $3.20 (18%)       │
│ Conversation compression:  $1.80 (10%)       │
│ Free-first routing:        $0.90 (5%)        │
│                                              │
│ Total saved this month:    $18.30            │
│ You'd have spent:          $41.70 without BLD│
│ You actually spent:        $23.40            │
└──────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Tech |
|-------|------|
| Desktop | Electron + React 18 + TypeScript + Vite |
| Styling | Tailwind CSS |
| State | Zustand |
| Local Storage | electron-store |
| File Watching | chokidar |
| Screenshots | Puppeteer |
| Process Mgmt | node-pty |
| Mobile | React Native + Expo (later phase) |
| Backend | Supabase (auth, db, realtime, storage) |
| Edge Functions | Supabase Edge (Deno) |
| Payments | Stripe |
| AI Gateway | OpenRouter (400+ models) |
| Classification | Gemini Flash (free) |
| Validation VLM | Gemini Flash (free) |
| Local Models | Ollama |

---

## Project Structure

```
bld/
├── src/
│   ├── main/                        # Electron main process
│   │   ├── index.ts                 # Entry, window management ✅ DONE
│   │   ├── tray.ts                  # System tray ✅ DONE
│   │   ├── ipc.ts                   # IPC handlers ✅ DONE
│   │   ├── agents/
│   │   │   ├── openrouter.ts        # OpenRouter API client ✅ DONE
│   │   │   ├── ollama.ts            # Local Ollama ✅ DONE
│   │   │   └── manager.ts           # Agent lifecycle management
│   │   ├── classification/
│   │   │   └── classifier.ts        # Task classification ✅ DONE
│   │   ├── optimization/
│   │   │   ├── cache.ts             # Prompt caching manager
│   │   │   ├── context.ts           # Smart context windowing
│   │   │   ├── compression.ts       # Conversation compression
│   │   │   └── router.ts            # Free-first model routing
│   │   ├── validation/
│   │   │   ├── screenshot.ts        # Puppeteer screenshots ✅ DONE
│   │   │   ├── vlm.ts              # Gemini validation ✅ DONE
│   │   │   └── error-collector.ts   # Error context collector for retry loop
│   │   ├── tasks/
│   │   │   ├── queue.ts             # Task queue management
│   │   │   └── chunker.ts           # Task → subtask decomposition
│   │   └── recording/
│   │       └── replay.ts            # Session recording
│   ├── renderer/                    # React UI
│   │   ├── App.tsx                  # Root with sidebar layout ✅ DONE
│   │   ├── main.tsx                 # Entry point ✅ DONE
│   │   ├── components/
│   │   │   ├── Sidebar.tsx          # Workspace navigation ✅ DONE
│   │   │   ├── Dashboard.tsx        # Agent grid + task input + queue ✅ DONE
│   │   │   ├── AgentCard.tsx        # Agent card (terminal/preview/screenshot feeds) ✅ DONE
│   │   │   ├── AgentRoster.tsx      # Agent roster management ✅ DONE
│   │   │   ├── FlowsView.tsx        # Flow workstreams with subtasks ✅ DONE
│   │   │   ├── BudgetView.tsx       # Budget + token savings dashboard ✅ DONE
│   │   │   ├── TaskInput.tsx        # Task input with project/model selectors ✅ DONE
│   │   │   ├── TaskQueue.tsx        # Queue display ✅ DONE
│   │   │   ├── AddProjectDialog.tsx # Add project dialog ✅ DONE
│   │   │   ├── AgentFeed.tsx        # Fullscreen agent view
│   │   │   ├── DiffViewer.tsx       # Code diff display
│   │   │   ├── PiPWindow.tsx        # Picture-in-picture
│   │   │   ├── Stats.tsx            # Usage stats
│   │   │   ├── Settings.tsx         # Settings panel
│   │   │   └── Credits.tsx          # Credit balance/purchase
│   │   ├── stores/
│   │   │   ├── agentStore.ts        # ✅ DONE
│   │   │   ├── taskStore.ts         # ✅ DONE
│   │   │   ├── settingsStore.ts     # ✅ DONE
│   │   │   ├── projectStore.ts      # ✅ DONE
│   │   │   └── creditsStore.ts
│   │   └── styles/
│   │       └── globals.css          # ✅ DONE
│   ├── preload/
│   │   └── index.ts                 # ✅ DONE
│   └── shared/
│       └── types.ts                 # ✅ DONE
├── supabase/
│   ├── functions/
│   │   ├── chat/index.ts            # OpenRouter proxy
│   │   ├── classify/index.ts        # Task classification
│   │   ├── validate/index.ts        # VLM validation
│   │   └── credits/index.ts         # Credit management
│   └── migrations/
├── electron.vite.config.ts          # ✅ DONE
├── package.json                     # ✅ DONE
├── tailwind.config.js               # ✅ DONE
├── postcss.config.js                # ✅ DONE
├── tsconfig.json                    # ✅ DONE
├── TASKS.md
└── CLAUDE.md
```

---

## Core Features to Build

### 1. Workspace Layout ✅ DONE

Sidebar navigation with five views:
- **Dashboard** — agent grid + task input + queue
- **Agents** — roster management (enable/disable, set specialties, see costs)
- **Flows** — workstreams broken into agent-assigned subtasks
- **Budget** — spend tracking, burn rate, token savings dashboard
- **Settings** — API keys, preferences

### 2. Agent Cards with Three Feed Modes ✅ DONE

Each agent card auto-switches its feed based on status:

| Agent Status | Feed Mode | What You See |
|---|---|---|
| `running` | **Terminal** | Scrolling CLI output from the agent |
| `validating` | **Live Preview** | Embedded webview of dev server (see the app live) |
| `done` | **Screenshot** | Final validation screenshot with "Passed" badge |
| `error` | **Screenshot** | Failure screenshot with "Failed" badge |

Card layout: Header (name + model + status badge) → Progress bar → Feed area → Current task

Click a card to expand to fullscreen view with:
- Large live feed / interactive webview
- Real-time log output
- Files changed (live diff)
- Confidence meter
- Approve/Reject buttons

### 3. Task Input ✅ DONE

Input bar at top of dashboard with project selector and model picker:

```
┌─────────────────────────────────────────────────────────────────┐
│ What do you want to build in my-app?                [SEND]     │
│ ─────────────────────────────────────────────────────────────  │
│ Project: [my-app ▼]  |  Model: [Auto ▼]  |  ~/projects/my-app  │
└─────────────────────────────────────────────────────────────────┘
```

When submitted:
1. **Chunk task** into subtasks (see Task Chunking below)
2. **Classify** each subtask → route to appropriate agent/model
3. Add to queue
4. Start execution when agent available

### 3a. Task Queue ✅ DONE

```
┌─ QUEUE ─────────────────────────────────────────────────────────┐
│ 1. "add dark mode"         Claude Sonnet    ~5 min    [Cancel] │
│ 2. "write api tests"       GPT-5            ~8 min    [Cancel] │
│ 3. "fix mobile nav"        Ollama           ~3 min    [Cancel] │
└─────────────────────────────────────────────────────────────────┘
```

Support smart queue parsing: "after dark mode, add settings page, then have ollama review both"

### 4. Task Chunking

When a user gives a task (e.g., "Add dark mode"), it gets broken into subtasks. Each subtask can be routed to a different agent/model.

**Two-tier chunking strategy:**
1. **Free heuristic** (default, free) — Pattern-based splitting. Ex: "Contains CSS" → route to Cursor
2. **LLM chunking** (fallback, costs $$) — Use Claude to intelligently decompose. Ex: Ask Claude to analyze task and split. More expensive but better results.

```
User: "Add dark mode"
  ├── Subtask 1: "Implement CSS color scheme"     → Cursor (CSS specialist)
  └── Subtask 2: "Implement color changing logic"  → Claude (logic specialist)
```

### 5. Classification

**How to classify subtasks → agents:**
- Users can **predetermine models** for certain task types (e.g., "always use Cursor for CSS")
- Classifier uses free heuristic first, LLM fallback for ambiguous tasks
- Different agents have different strengths:
  - **Cursor** → IDE-based tasks (CSS, UI changes)
  - **Claude** → Logic, architecture, complex reasoning (via CLI)
  - **Ollama** → Local tasks, privacy-sensitive, free tier

### 6. Agent Types

| Agent | Interface | Notes |
|-------|-----------|-------|
| **Claude** | CLI | Direct CLI invocation |
| **Ollama** | CLI | Local models, always free |
| **Cursor** | Listener | Build a listener that interfaces with Cursor IDE |

> Open question: Do users have to install Cursor/Claude/etc.? [3]

### 7. Validation Flow (Three-Tier Confidence)

When a subtask completes:
1. Take screenshot of output
2. Run tests / hit API endpoints (if available)
3. Capture **all output** — console logs, API responses, error messages, stack traces
4. Get git diff
5. Send everything to **VLM** (Claude Vision / Gemini) to compare output to subtask requirements

**Confidence routing:**

```
VLM compares output to subtask
         │
         ├── ≥85% confidence → Auto-approve, notify user "done"
         │
         ├── 5-85% confidence → RETRY LOOP (see below)
         │
         └── <5% confidence → Immediately notify user w/ data asking for approval
```

### 7a. Self-Healing Retry Loop

This is the core differentiator. When something fails, **don't just say "it failed"** — capture the full diagnostic context and feed it back to the agent so it can fix itself. This mimics the workflow of copy-pasting error output to Claude and having it fix the issue.

**How it works:**

```
Subtask fails or confidence is 5-85%
         │
         ▼
┌─────────────────────────────────────────────────┐
│ CAPTURE DETAILED ERROR CONTEXT                  │
│                                                 │
│ • Screenshot of the broken output               │
│ • Full API error response (status, body, headers)│
│ • Stack trace / console errors                  │
│ • Test output (which tests failed and why)      │
│ • Terminal/CLI output from the agent             │
│ • Git diff of what was changed                  │
│ • The original subtask prompt                   │
│ • VLM's explanation of what looks wrong         │
└─────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────┐
│ BUILD DESCRIPTIVE ERROR PROMPT                  │
│                                                 │
│ "You were asked to [subtask]. Here's what       │
│  happened:                                      │
│  - API returned 422: {full error body}          │
│  - Test `auth.test.ts` failed: expected 200,    │
│    got 401 at line 47                           │
│  - Screenshot shows: [base64 image]             │
│  - VLM analysis: 'Login form renders but        │
│    submit button triggers 422 because the       │
│    email validation regex rejects valid emails'  │
│                                                 │
│  Fix these issues."                             │
└─────────────────────────────────────────────────┘
         │
         ▼
    Agent re-executes with full context
         │
         ▼
    Re-validate (screenshot + tests + API)
         │
         ├── Pass → Auto-approve, notify user "done"
         │
         └── Fail again → After retry limit (configurable, default 2x)
                  → Notify user w/ ALL collected data asking for approval
```

**Key principle:** The error prompt must be so descriptive that looking at it tells you exactly what went wrong. Include the raw error, the screenshot, the test output, and the VLM's analysis — everything the agent needs to self-correct without human help.

**Mobile notification (when retries exhausted) includes:** Screenshot, confidence score, model used, diff, full error context, retry history (what was tried and why it failed each time).

**How to check for function (not just visual)?**
- Screenshots check visual output
- Run tests check functional correctness
- Hit API endpoints and capture full response (status, body, headers)
- Capture console/terminal output for runtime errors
- Video/interaction recording for UI flows → Later phase

### 8. Git Safety System

Git safety system to protect user's codebase during agent execution. (Details TBD — version control, branching strategy, rollback on failure.)

### 9. User Nuances

- **Model preferences per task type** — User can predetermine which models handle certain tasks (e.g., "Cursor for CSS")
- **Configurable accuracy threshold** — Users decide what confidence score triggers mobile notifications

### 10. Picture-in-Picture

Floating mini window showing active agent:

```
┌───────────────────┐
│ Claude ████░░ 72% │
│ [mini live feed]  │
└───────────────────┘
```

Always on top, draggable, click to expand.

### 11. Stats (Light Gamification)

```
┌─ YOUR WEEK ──────────────────────────┐
│ Tasks completed:     47              │
│ Hours saved:         ~8.3            │
│ Lines generated:     2,847           │
│ Approval rate:       94%             │
│                                      │
│ 🔥 12-day streak                     │
└──────────────────────────────────────┘
```

### 12. Settings

- API key management (OpenRouter or BYOK)
- Default model selection
- Confidence threshold
- Sound on/off
- PiP on/off
- Project management

### 13. Credits

For Pro users (not BYOK):

```
┌─ CREDITS ────────────────────────────┐
│ Balance: $47.20                      │
│                                      │
│ [+ Add $20] [+ Add $50] [+ Add $100] │
│                                      │
│ Recent:                              │
│ • Claude Sonnet - "fix auth" - $0.12 │
│ • Gemini Flash - validation - $0.00  │
└──────────────────────────────────────┘
```

---

## Design System

| Element | Value |
|---------|-------|
| Font | Inter (400, 500, 600, 700) |
| Primary | #6366F1 (indigo-500) |
| Success | #22C55E (green-500) |
| Warning | #F59E0B (amber-500) |
| Error | #EF4444 (red-500) |
| Background | #09090B (zinc-950) |
| Surface | #18181B (zinc-900) |
| Surface hover | #27272A (zinc-800) |
| Border | #3F3F46 (zinc-700) |
| Text | #FAFAFA (zinc-50) |
| Text muted | #A1A1AA (zinc-400) |
| Border radius | 8px (cards), 6px (buttons), 4px (inputs) |

Dark mode only for MVP.

---

## Database Schema (Supabase)

```sql
-- Profiles (extends auth.users)
create table profiles (
  id uuid primary key references auth.users(id),
  email text,
  tier text default 'free', -- free, pro, pro_byok, team
  credits numeric default 0,
  stripe_customer_id text,
  created_at timestamptz default now()
);

-- Projects
create table projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references profiles(id),
  name text not null,
  directory text not null,
  dev_server_url text,
  confidence_threshold int default 80,
  default_model text default 'anthropic/claude-sonnet-4.6',
  created_at timestamptz default now()
);

-- Tasks
create table tasks (
  id uuid primary key default gen_random_uuid(),
  project_id uuid references projects(id),
  user_id uuid references profiles(id),
  prompt text not null,
  status text default 'queued', -- queued, running, validating, needs_review, approved, rejected
  model text,
  classification jsonb,
  confidence int,
  reasoning text,
  cost numeric,
  files_changed jsonb,
  diff text,
  before_screenshot text,
  after_screenshot text,
  auto_approved boolean default false,
  human_verdict text,
  created_at timestamptz default now(),
  completed_at timestamptz
);

-- Credit Transactions
create table credit_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references profiles(id),
  amount numeric not null,
  type text not null, -- purchase, task, refund
  task_id uuid references tasks(id),
  stripe_payment_id text,
  created_at timestamptz default now()
);

-- Daily Stats
create table daily_stats (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references profiles(id),
  date date not null,
  tasks_completed int default 0,
  tasks_approved int default 0,
  tasks_rejected int default 0,
  credits_spent numeric default 0,
  streak_days int default 0,
  unique(user_id, date)
);
```

---

## IPC Events

### Main → Renderer

```typescript
'task:created': Task
'task:updated': Task
'task:completed': Task
'agent:frame': { agentId: string; frame: string }  // Live screenshot
'agent:output': { agentId: string; line: string }  // Log line
'agent:status': { agentId: string; status: string; progress: number }
'credits:updated': number
```

### Renderer → Main

```typescript
'task:submit': { prompt: string; projectId: string; model?: string }
'task:approve': taskId
'task:reject': taskId
'task:retry': { taskId: string; feedback?: string }
'settings:get': void
'settings:set': Partial<Settings>
'credits:purchase': amount
'ollama:check': void
'project:select': projectId
```

---

## Key Files to Create

### 1. src/main/index.ts

Electron main process:
- Create main window
- Setup tray
- Initialize IPC handlers
- Watch for Ollama
- Manage agent processes

### 2. src/main/ipc.ts

All IPC handlers:
- Task submission → classify → queue → execute
- Validation flow
- Settings management
- Credit operations

### 3. src/main/tasks/queue.ts

Task queue manager:
- Priority queue
- Dependency parsing ("after X, do Y")
- Agent assignment
- Status tracking

### 4. src/main/agents/manager.ts

Agent lifecycle:
- Spawn agent processes (node-pty)
- Capture output streams
- Stream browser screenshots (Puppeteer)
- Handle completion/errors

### 5. src/renderer/App.tsx

Main React app:
- Router (if needed)
- Global providers
- Layout

### 6. src/renderer/components/Dashboard.tsx

Security camera grid:
- Map agents to AgentCard components
- Handle card expansion
- Task input at top
- Queue at bottom

### 7. src/renderer/components/AgentCard.tsx

Individual agent card:
- Live frame display (updated via IPC)
- Progress bar
- Status indicator
- Task description
- Click to expand

### 8. src/renderer/stores/agentStore.ts

Zustand store for agents:
```typescript
interface AgentStore {
  agents: Record<string, Agent>;
  activeAgentId: string | null;
  addAgent: (agent: Agent) => void;
  updateAgent: (id: string, updates: Partial<Agent>) => void;
  setActiveAgent: (id: string | null) => void;
}
```

### 9. src/renderer/stores/taskStore.ts

Zustand store for tasks:
```typescript
interface TaskStore {
  tasks: Task[];
  queue: Task[];
  addTask: (task: Task) => void;
  updateTask: (id: string, updates: Partial<Task>) => void;
  approveTask: (id: string) => void;
  rejectTask: (id: string) => void;
}
```

---

## API Routes (Supabase Edge Functions)

### POST /functions/v1/chat

Proxy to OpenRouter (uses our API key, charges user credits):

```typescript
// Request
{ model: string, messages: Message[], task_id: string }

// Response
{ content: string, usage: { input_tokens, output_tokens }, cost: number }
```

### POST /functions/v1/classify

Classify task (uses Gemini Free):

```typescript
// Request
{ prompt: string }

// Response
{ type, complexity, suggested_model, reasoning }
```

### POST /functions/v1/validate

VLM validation (uses Gemini Free):

```typescript
// Request
{ before_screenshot, after_screenshot, prompt, diff }

// Response
{ confidence, reasoning, issues }
```

---

## Environment Variables

```bash
# Desktop (.env)
SUPABASE_URL=
SUPABASE_ANON_KEY=

# Supabase Edge Functions
OPENROUTER_API_KEY=      # Our master key
GEMINI_API_KEY=          # For free classification/validation
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
```

---

## Build Order

1. **Electron shell** - Window, tray, basic IPC
2. **Dashboard UI** - Grid layout, mock agent cards
3. **Agent manager** - Spawn processes, capture output
4. **Live feeds** - Puppeteer screencast → IPC → React
5. **Task flow** - Input → classify → queue → execute
6. **Validation** - Screenshots → VLM → confidence
7. **Settings** - API keys, preferences
8. **Credits** - Stripe integration (if Pro)
9. **Polish** - Sounds, PiP, stats

---

## Commands

```bash
npm run dev          # Start Electron dev
npm run build        # Build for production
npm run package      # Package for distribution
```

---

## Open Questions (from whiteboard)

1. **How are we chunking?** — Free heuristic vs LLM chunking tradeoff (cost vs quality)
2. **How to classify?** — Heuristic-first with LLM fallback decided, but rules TBD
3. **Do users have to install Cursor/Claude/etc?** — CLI agents (Claude, Ollama) are straightforward; Cursor needs a listener/bridge
4. **User approval flow** — Allow for user approval after task completion? When exactly?
5. **How to check for function?** — Screenshots check visual, but how do we verify interactive behavior (e.g., form submission triggers action)? Video recording? Run tests? What VLM/approach?
6. **Claude Vision** — Use as VLM for validation instead of/alongside Gemini?

---

## Notes

- Use `electron-vite` for the build system (already configured)
- Live feed frames come via IPC as base64 images at ~12fps
- Classification and validation are free (Gemini / Claude Vision)
- Agent execution costs user credits (OpenRouter) or their own keys (BYOK)
- Store API keys securely with electron-store (encrypted)
- All AI calls for Pro users go through our Supabase edge functions
- BYOK users call providers directly from the Electron app
- Local models (Ollama) are always free regardless of tier
- Prop interactions + video capture for validation is a later-phase feature