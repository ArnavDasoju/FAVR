# BLD — Build Tasks

Chunked from CLAUDE.md. Each phase is self-contained and shippable. Check off as you go.

---

## Phase 1: Electron Shell ✅ COMPLETE
> Goal: `npm run dev` opens a window with a tray icon.

- [x] `electron.vite.config.ts` — Vite config for main/renderer/preload
- [x] `tsconfig.json` — TypeScript config (paths, strict mode)
- [x] `tailwind.config.js` — Tailwind with design system colors/fonts
- [x] `postcss.config.js` — PostCSS config
- [x] `src/main/index.ts` — Create BrowserWindow, load renderer, app lifecycle, webview enabled
- [x] `src/preload/index.ts` — contextBridge exposing IPC invoke/on methods to renderer
- [x] `src/main/tray.ts` — System tray icon + context menu (Show/Hide, Quit)
- [x] `src/renderer/styles/globals.css` — Tailwind directives + CSS variables for design tokens
- [x] **Verify:** `npm run dev` → window opens, tray icon visible, dark background

---

## Phase 2: Workspace UI ✅ COMPLETE
> Goal: Full workspace layout with sidebar, agent grid, workspace views.

- [x] `src/renderer/App.tsx` — Root with sidebar layout, view routing
- [x] `src/renderer/main.tsx` — Entry point
- [x] `src/renderer/components/Sidebar.tsx` — Workspace nav (Dashboard, Agents, Flows, Budget, Settings) + budget widget
- [x] `src/renderer/components/Dashboard.tsx` — Agent grid + task input + queue with mock data
- [x] `src/renderer/components/AgentCard.tsx` — Three feed modes (terminal/preview/screenshot), auto-switches by status
- [x] `src/renderer/components/TaskInput.tsx` — Input + project selector + model picker + directory path display
- [x] `src/renderer/components/TaskQueue.tsx` — Queue display with cancel buttons
- [x] `src/renderer/components/AddProjectDialog.tsx` — Add project dialog with Browse (native OS file picker)
- [x] `src/renderer/components/AgentRoster.tsx` — Agent roster: enable/disable, set specialties, cost display, toggle switches
- [x] `src/renderer/components/FlowsView.tsx` — Flow workstreams with expandable subtask lists, agent assignments, cost estimates
- [x] `src/renderer/components/BudgetView.tsx` — Budget stats, progress bar, token savings dashboard, agent spend breakdown, recent activity
- [x] `src/shared/types.ts` — All types (Agent with FeedMode, Task, Subtask, Project, Settings, etc.)
- [x] **Verify:** Sidebar nav works, all views render, project selector works, grayscale bold design

---

## Phase 3: Zustand Stores + IPC Wiring ✅ COMPLETE
> Goal: Type a task → it flows through IPC → appears in UI state.

- [x] `src/renderer/stores/agentStore.ts` — Zustand: agents map, activeAgentId, add/update/setActive, appendOutput, setFrame, setStatus
- [x] `src/renderer/stores/taskStore.ts` — Zustand: tasks array, add/update/remove/setStatus
- [x] `src/renderer/stores/settingsStore.ts` — Zustand: apiKeys, defaultModel, confidenceThreshold, retryLimit, modelPreferences
- [x] `src/renderer/stores/projectStore.ts` — Zustand: projects, activeProjectId, add/remove/setActive
- [x] `src/main/ipc.ts` — All IPC handlers (task, agent, settings, project, stats, ollama)
- [x] Dashboard reads from Zustand stores, calls IPC for task submit/cancel
- [x] TaskInput calls `window.api.invoke('task:submit', ...)` → main process → IPC back
- [x] IPC listeners: task:created, task:updated, agent:status, agent:output, agent:frame → update stores
- [x] Projects persist via electron-store, restore on app launch
- [x] **Verify:** App launches, settings load, projects persist across restarts

---

## Phase 4: Task Chunking + Classification ✅ COMPLETE
> Goal: Submit "Add dark mode" → system chunks it into subtasks → classifies each → routes to agents.

- [x] `src/main/tasks/chunker.ts` — Two-tier task decomposition (heuristic pattern matching + LLM fallback)
- [x] `src/main/tasks/queue.ts` — Full task queue with submit → chunk → route → execute → validate loop
- [x] `src/main/optimization/router.ts` — Free-first model routing (Ollama → Gemini → DeepSeek → Claude → GPT)
- [x] Model priority: user explicit > user preferences per type > free-first router
- [ ] Update FlowsView.tsx to show real flows from store instead of mocks
- [x] **Verify:** Queue chunks tasks, assigns models via router, manages subtask lifecycle

---

## Phase 5: Agent Manager + Validation Pipeline ✅ COMPLETE
> Goal: Subtask starts → agent process spawns → output streams to UI → validates → retries if needed.

- [x] `src/main/agents/manager.ts` — Agent lifecycle (Ollama NDJSON streaming, OpenRouter SSE streaming, kill support, token budgets)
- [x] `src/main/validation/screenshot.ts` — Puppeteer screenshot capture (optional, graceful degradation)
- [x] `src/main/validation/vlm.ts` — Gemini Flash VLM validation (free, vision + text-only modes)
- [x] `src/main/validation/error-collector.ts` — Full error context collection (tests, diff, stack traces, console output)
- [x] `src/main/validation/validator.ts` — Validation orchestrator: screenshot → VLM → confidence routing → error prompt builder
- [x] Queue → Agent Manager wiring: queue.processNext() spawns agents via agentManager.spawn()
- [x] Full self-healing loop: agent completes → validate → ≥85% auto-approve / 5-84% retry with error prompt / <5% human review
- [x] Ollama auto-detection on startup
- [ ] AgentCard terminal feed shows real-time output from live agents (needs store wiring)
- [ ] Progress bar reflects actual agent progress (needs store wiring)
- [x] **Verify:** Type-checks clean, builds successfully

---

## Phase 6: Token Optimization Engine ✅ COMPLETE
> Goal: Aggressively reduce token usage to stretch user credits.

- [x] `src/main/optimization/cache.ts` — Prompt caching manager (project snapshot, mtime-based invalidation, cache_control hints)
- [x] `src/main/optimization/context.ts` — Smart context windowing (import tracing, keyword file matching, token budget)
- [x] `src/main/optimization/compression.ts` — Conversation compression (Gemini Flash summary, heuristic fallback, diff-based updates)
- [x] `src/main/optimization/router.ts` — Free-first model routing (Ollama → Gemini → DeepSeek → Claude → GPT)
- [x] Token budgets per complexity wired into agent manager
- [x] Diff-based update utility in compression module
- [x] Prompt cache wired into agent manager system prompts
- [ ] Wire savings data to BudgetView token optimization panel (needs store wiring)

---

## Phase 7: Live Feeds (Screenshots + Preview)
> Goal: Agent cards show live browser screenshots and embedded dev server preview during validation.

- [ ] Wire screenshot.ts (already done) to capture periodic screenshots of dev server
  - Configurable interval (~12fps = every ~83ms for active, slower for idle)
  - Before/after snapshots saved for validation
- [ ] Stream frames via IPC `agent:frame` as base64 strings
- [ ] AgentCard terminal → screenshot feed transition (already coded, just needs real data)
- [ ] AgentCard `preview` feed mode — embedded webview of dev server during validation (already coded)
  - Webview loads project's `devServerUrl`
  - Non-interactive overlay in card view (click to expand)
  - "Checking..." badge during validation
- [ ] AgentCard `screenshot` feed mode — final validation screenshot with Passed/Failed badge (already coded)
- [ ] Frame rate throttling (skip frames if renderer is behind)
- [ ] **Verify:** Agent running → terminal feed → validation starts → switches to live preview → done → shows screenshot with badge

---

## Phase 8: Self-Healing Validation Loop ✅ COMPLETE (merged into Phase 5)
> Implemented as part of Phase 5 — the validation pipeline is built into the queue execution loop.

- [x] `src/main/validation/error-collector.ts` — Error context collector (tests, diff, stack traces, console, VLM)
- [x] `src/main/validation/vlm.ts` — Gemini Flash vision validation (free tier)
- [x] `src/main/validation/screenshot.ts` — Puppeteer screenshot + console error capture
- [x] `src/main/validation/validator.ts` — Full orchestrator with heuristic fallback
- [x] Descriptive error prompt builder feeds full context back to agent on retry
- [x] Confidence routing: ≥85% auto-approve, 5-84% retry with error context, <5% human review
- [x] Retry loop with configurable limit (default 2)

---

## Phase 9: Expanded Agent View
> Goal: Click an agent card → fullscreen detail view with logs, diff, approve/reject.

- [ ] `src/renderer/components/AgentFeed.tsx` — Fullscreen agent view:
  - Large live feed / interactive webview (preview mode is interactive here, not just visual)
  - Real-time scrolling log output
  - Confidence meter (visual gauge)
  - Current subtask description
  - Retry history (if in validation loop — show each attempt and what failed)
- [ ] `src/renderer/components/DiffViewer.tsx` — Code diff display:
  - Files changed list
  - Inline diff view (green/red lines)
  - Syntax highlighting
- [ ] Approve/Reject buttons in AgentFeed → wire to `task:approve` / `task:reject` IPC
- [ ] Retry with feedback — text input for user to add context when rejecting
- [ ] Click AgentCard → expand to AgentFeed (animation optional)
- [ ] Back button / ESC to return to dashboard
- [ ] **Verify:** Click agent card → see full detail → view diff → approve or reject → returns to dashboard

---

## Phase 10: Settings + Persistence ✅ COMPLETE
> Goal: Configure API keys, model preferences, thresholds. Persists across restarts.

- [x] `src/renderer/components/Settings.tsx` — Full settings page (API keys, Ollama status, model prefs, confidence slider, retry limit, project management)
- [x] `src/main/store.ts` — electron-store persistence with basic encryption for API keys
- [x] Wire settings:get / settings:set IPC → read/write electron-store → push to queue/agentManager
- [x] Load settings + projects on app start → populate stores + backend modules
- [x] Projects persist across restarts (directory, dev server URL)

---

## Phase 11: Credits + Stats + Polish
> Goal: Credit balance, purchase flow, weekly stats, PiP, sounds.

- [ ] `src/renderer/stores/creditsStore.ts` — Zustand: balance, transactions, add/deduct
- [ ] `src/renderer/components/Credits.tsx` — Credit balance display, purchase buttons ($20/$50/$100), recent transactions list
- [ ] `src/renderer/components/Stats.tsx` — Weekly stats: tasks completed, hours saved, lines generated, approval rate, streak counter
- [ ] `src/renderer/components/PiPWindow.tsx` — Floating always-on-top mini window:
  - Shows active agent name + progress bar + mini live feed
  - Draggable
  - Click to expand back to main window
- [ ] Sound notifications (task complete, needs approval, error)
- [ ] Mobile notification prep — hooks/interfaces for push notifications (React Native integration point for later)
- [ ] **Verify:** See credit balance → mock a purchase → balance updates. Check stats page. PiP floats on top. Sounds play on events.

---

## Phase 12: Git Safety System ✅ COMPLETE
> Goal: Protect user's codebase during agent execution.

- [x] `src/main/git/safety.ts` — Full git safety module (branch create, commit, merge, reject, cleanup)
- [x] Auto-create branch `bld/task-{id}` before agent starts
- [x] Stash uncommitted changes before branching
- [x] Commit agent changes to branch (not main)
- [x] On approval → merge branch back via `--no-ff`, restore stash
- [x] On rejection → force-delete branch, restore stash
- [x] Wired into queue.ts execution pipeline (branch on start, commit after agent, merge/reject on user action)
- [x] Handle concurrent agents via separate branches per subtask

---

## Phase 13: Supabase Backend
> Goal: Auth, cloud sync, edge functions for Pro users.

- [ ] Supabase project setup + migrations (profiles, projects, tasks, credit_transactions, daily_stats)
- [ ] `supabase/functions/chat/index.ts` — OpenRouter proxy (our API key, charge user credits)
- [ ] `supabase/functions/classify/index.ts` — Task classification via Gemini Free
- [ ] `supabase/functions/validate/index.ts` — VLM validation via Gemini Free
- [ ] `supabase/functions/credits/index.ts` — Credit management + Stripe integration
- [ ] Auth flow in Electron (Supabase auth, store session)
- [ ] Sync tasks/stats to cloud for Pro users
- [ ] **Verify:** Sign up → sign in → submit task as Pro → goes through edge function → credits deducted

---

## Summary

| Phase | What | Status | Depends On |
|-------|------|--------|------------|
| 1 | Electron Shell | ✅ Done | Nothing |
| 2 | Workspace UI | ✅ Done | Phase 1 |
| 3 | Stores + IPC Wiring | ✅ Done | Phase 2 |
| 4 | Task Chunking + Classification | ✅ Done | Phase 3 |
| 5 | Agent Manager + Validation | ✅ Done | Phase 3 + 4 |
| 6 | Token Optimization Engine | ✅ Done | Phase 5 |
| 7 | Live Feeds + Preview | ⬜ | Phase 5 |
| 8 | Self-Healing Validation | ✅ Done (in Phase 5) | — |
| 9 | Expanded Agent View | ⬜ | Phase 7 |
| 10 | Settings + Persistence | ✅ Done | Phase 3 |
| 11 | Credits + Stats + Polish | ⬜ | Phase 10 |
| 12 | Git Safety | ✅ Done | Phase 5 |
| 13 | Supabase Backend | ⬜ | Phase 10 |

**Parallelizable:** Phases 10 + 12 can run alongside Phases 7-9. Phase 6 can start as soon as Phase 5 is done.
