---
type: project-tasks-polish
scope: FAVR — Hackathon Final Polish
status: Engine ~95% complete, focus is demo-ready polish
---

# Tasks — FAVR Hackathon Polish

The engine, charts, IPC, stores, and demo data are all working. These chunks focus on the polish that makes judges go "wow." Each chunk is scoped so you can hand it to Claude Code as a single prompt and get a clean commit.

Do them in order. Earlier chunks unlock the impact of later ones.

---

## Chunk 1: Global Animations & Transitions
**Why first:** This is the single biggest "feel" upgrade. Right now the UI is functional but static. Judges notice motion before they notice features.
**Estimated time:** 1-2 hours

- [ ] **1.1** Add a shared CSS transitions file (`src/renderer/styles/animations.css` or equivalent). Define reusable keyframes: `fadeIn`, `slideUp`, `scaleIn`, `pulseGlow`. Keep durations between 200-400ms with `ease-out` curves. Import globally.
- [ ] **1.2** Add staggered fade-in to all dashboard cards/panels. Each card should animate in with a 50-80ms delay after the previous one. Use CSS `animation-delay` or a lightweight stagger util — no heavy libraries.
- [ ] **1.3** Add smooth transitions to sidebar/nav item switches. Active tab indicator should slide (not jump) between items. Content area should crossfade on view change.
- [ ] **1.4** Add hover micro-interactions to all clickable elements — subtle scale (1.02), shadow lift, or brightness shift. Keep it consistent across buttons, cards, nav items.
- [ ] **1.5** Add a pulse/glow effect to the system risk score number and any "critical" severity badges. Subtle but draws the eye.
- [ ] **1.6** Test every animation at 2x speed to make sure nothing feels sluggish during a live demo. Trim anything over 400ms.

**Done when:** Opening the app and clicking through all views feels fluid, not jumpy. Nothing pops in — everything glides.

---

## Chunk 2: Scan Flow — The Money Shot
**Why second:** "Browse → Scan → Results" is literally the demo. If this doesn't feel slick, nothing else matters.
**Estimated time:** 2-3 hours

- [ ] **2.1** Design the empty/landing state for the dashboard before any scan. Show the app name, a one-liner tagline ("Point at your codebase. Get a mathematically optimal patching plan."), and a prominent "Browse Codebase" button with a folder icon. No clutter — this screen should feel like a premium product launch page.
- [ ] **2.2** Wire up the Browse button to open a native OS directory picker (Electron `dialog.showOpenDialog`). On selection, show the selected path in a styled breadcrumb/chip below the button.
- [ ] **2.3** Build a multi-stage progress UI for the scan. NOT a single progress bar. Each phase gets its own line item that appears sequentially with a status indicator:
  - `◯ Discovering services...` → `✓ Found 5 services`
  - `◯ Querying packages...` → `✓ Queried 47 packages`
  - `◯ Looking up vulnerabilities...` → `✓ Found 12 vulnerabilities (3 critical)`
  - `◯ Building attack graph...` → `✓ 18 nodes, 24 edges`
  - `◯ Running Bayesian propagation...` → `✓ Risk scores computed`
  - `◯ Monte Carlo simulation (1000 runs)...` → `✓ Optimal order found`
  - `◯ Generating results...` → `✓ Analysis complete`
- [ ] **2.4** Each phase line should animate in (slide + fade from Chunk 1). The active phase should have a spinning/pulsing indicator. Completed phases get a green checkmark with a brief flash.
- [ ] **2.5** Add real-time count-up animations for the numbers ("Found 5 services" — the 5 should tick up from 0). Use `requestAnimationFrame` or a small counter util.
- [ ] **2.6** When all phases complete, auto-transition (with a 500ms pause for satisfaction) into the results dashboard. The results panels should stagger in from Chunk 1.
- [ ] **2.7** Add a subtle success sound on scan completion (short chime, ~0.3s). Include a mute option but default to on. Keep the audio file tiny (<50KB).
- [ ] **2.8** Test the full flow end-to-end with a real repo. Time it. If any phase takes >5s with no visual feedback, add a secondary animation or log line to fill the gap.

**Done when:** You can screen-record Browse → Scan → Results and it looks like a product trailer, not a hackathon prototype.

---

## Chunk 3: Results Dashboard Polish
**Why third:** Once the scan lands, judges stare at this screen. Every element needs to communicate value.
**Estimated time:** 1.5-2 hours

- [ ] **3.1** Style the top-level metrics row (system risk score, risk reduction %, vuln count, critical count, compliance risk). Each metric should be in its own card with a large primary number, a label, and an icon or color accent. Risk score gets the pulse from 1.5.
- [ ] **3.2** Add count-up animation to all metric numbers on first render (same technique as 2.5). Numbers should land on their final value within 600-800ms.
- [ ] **3.3** Review the dependency graph (D3 force-directed). Make sure node colors clearly map to severity (green → yellow → orange → red). Add tooltips on hover showing package name, version, CVE count. If edges are hard to read, add directional arrows or animate the edge flow.
- [ ] **3.4** Review the service heatmap. Make sure the color scale is intuitive (cool → hot). Add labels to each cell. Hover should show exact propagated risk score.
- [ ] **3.5** Style the Top 5 Priority Patches list. Each item should show: patch rank (#1-#5), package name, CVE ID, CVSS score, EPSS score, and a visual indicator when CVSS and EPSS diverge significantly (this is a key differentiator — call it out with a badge or icon like "⚠ EPSS disagrees").
- [ ] **3.6** Add a one-line explanation under each priority patch: "Why #1: High EPSS (73%) despite moderate CVSS (5.4) — actively exploited in the wild." Pull this from the analysis engine output.
- [ ] **3.7** Check that all 6 chart visualizations render without overlap, clipping, or text cutoff at typical window sizes (1280×720 minimum, 1920×1080 target).

**Done when:** A screenshot of the results dashboard could go in a pitch deck.

---

## Chunk 4: What-If Scenarios
**Why here:** This is the "wow" feature. Judges ask "so what?" — this answers it interactively.
**Estimated time:** 1-1.5 hours

- [ ] **4.1** Add a "What-If Analysis" section below the main results (or as a tab/panel). Include a slider or input for "Available patching budget (hours)" with a reasonable default (e.g., 40 hours).
- [ ] **4.2** When the budget value changes, re-run the Pareto optimization with the constraint and display: which patches fit in the budget, total risk reduction achieved, residual risk remaining.
- [ ] **4.3** Show a before/after comparison — maybe a simple bar or gauge showing current risk vs. residual risk with the selected patches applied. Animate the transition.
- [ ] **4.4** Add a "Maintenance Window" dropdown (e.g., "Next weekend — 8 hours", "Sprint — 40 hours", "Quarter — 160 hours") as presets for the budget slider. These are faster to demo than typing numbers.
- [ ] **4.5** If compliance deadlines are present, show a warning when the selected budget doesn't cover patches needed before a deadline: "⚠ PCI-DSS deadline in 12 days — 2 critical patches not covered by this budget."

**Done when:** You can slide the budget from 0 to max and watch risk drop in real-time. Judges can interact with it.

---

## Chunk 5: HTML Report Export
**Why here:** "Export a report" is a power move in a demo. Judges imagine forwarding it to their boss.
**Estimated time:** 1.5-2 hours

- [ ] **5.1** Review the current HTML report output. Open it in a browser. Check: does it have a professional header with date/project name? Is it readable without scrolling sideways? Do charts render inline (as static images or embedded SVG)?
- [ ] **5.2** Add a cover section to the report: project name, scan date, total vulns found, system risk score, a one-paragraph executive summary auto-generated from the analysis.
- [ ] **5.3** Add a "Priority Patches" table to the report with columns: Rank, Package, CVE, CVSS, EPSS, Estimated Hours, Recommended Deadline. Style it with alternating row colors.
- [ ] **5.4** Add a compliance section if applicable: which standards are at risk (PCI-DSS, HIPAA, SOC2), upcoming deadlines, patches needed to meet them.
- [ ] **5.5** Add a footer: "Generated by FAVR — Flexible Attack Vector Risk Analysis" with a timestamp.
- [ ] **5.6** Make sure the "Export Report" button in the app triggers a native Save dialog and writes the HTML file. Test opening the exported file in Chrome, Firefox, and Safari (if available).
- [ ] **5.7** Consider adding a "Print to PDF" hint or CSS `@media print` styles so the HTML also looks good when printed/PDF'd from a browser.

**Done when:** You'd feel comfortable emailing the exported report to a CISO and not apologizing for the formatting.

---

## Chunk 6: Loading States & Skeleton Screens
**Why here:** Prevents any moment where the app looks broken or frozen during a demo.
**Estimated time:** 45 min - 1 hour

- [ ] **6.1** Create a reusable skeleton component — animated gray placeholder bars/blocks that pulse (standard shimmer effect). Match the shape of the content they replace (cards = card-shaped skeleton, charts = chart-shaped skeleton).
- [ ] **6.2** Add skeletons to the results dashboard — show them immediately when scan completes and results are loading/rendering. Replace with real content as each section hydrates.
- [ ] **6.3** Add a skeleton or spinner to the D3 graph container. Force-directed layouts take a beat to stabilize — the skeleton covers that.
- [ ] **6.4** Add a loading indicator to the report export (if it takes >1s to generate). A small toast or inline spinner next to the Export button.

**Done when:** There's never a blank white rectangle visible at any point in the app flow.

---

## Chunk 7: Demo Prep & Safety Net
**Why last:** This isn't code — it's rehearsal. But it's the difference between winning and placing.
**Estimated time:** 1 hour

- [ ] **7.1** Pick your demo repo. Use a known-vulnerable open source project that has a good mix of severities (not all critical, not all low). Test the full scan against it and verify the results are interesting. Good candidates: an older version of a popular Node.js project, an intentionally vulnerable repo like OWASP Juice Shop or DVWA.
- [ ] **7.2** Do a full dry run of the demo flow start to finish. Time it. Aim for under 3 minutes total for the core flow (Browse → Scan → Results → What-If → Export). Practice your narration.
- [ ] **7.3** Pre-cache or pre-scan the demo repo so you have a fallback. If the live scan fails (network issue, API timeout), you can load cached results and keep going. Store the cached analysis JSON somewhere accessible.
- [ ] **7.4** Test on the actual machine/display you'll present on. Check resolution, font sizes, color contrast on a projector/TV. Bump up font sizes if anything is hard to read from 10 feet away.
- [ ] **7.5** Prepare a one-sentence answer for the obvious judge questions:
  - "How is this different from Snyk/Dependabot?" → "They sort by CVSS. We model risk propagation through your actual dependency graph and find the patch order that reduces total risk fastest."
  - "Does this scale?" → "Monte Carlo runs in <5s on 50+ CVEs. The bottleneck is API lookups, which are cached."
  - "What about false positives?" → "We use OSV.dev (Google's vulnerability database) and EPSS (real exploit probability), not heuristics."
- [ ] **7.6** Kill any desktop notifications, Slack, messages, OS update popups on the demo machine. Full-screen the app. Dark mode everything.

**Done when:** You've done the demo twice without fumbling, and you have a fallback plan if anything breaks live.

---

## Priority If You're Short On Time

**Must do (these win or lose it):**
- Chunk 2 (Scan Flow) — THE demo moment
- Chunk 3, sub-tasks 3.1-3.5 (Results Dashboard core polish)
- Chunk 7 (Demo Prep) — never skip rehearsal

**High value:**
- Chunk 1 (Animations) — makes everything feel 2x more polished
- Chunk 4, sub-tasks 4.1-4.3 (What-If basic version)
- Chunk 5, sub-tasks 5.1-5.3 (Report basics)

**Nice to have:**
- Chunk 6 (Skeletons) — good but not make-or-break
- Chunk 4, sub-tasks 4.4-4.5 (What-If presets + compliance warnings)
- Chunk 5, sub-tasks 5.4-5.7 (Report extras)

---

## How To Use This File With Claude Code

Copy a single chunk into Claude Code as your prompt. Example:

```
Here's what I need done next. Follow these sub-tasks in order:

[paste Chunk 2 here]

My project is an Electron + React app. The analysis engine is already working.
Don't rewrite working code — only add/modify what these tasks describe.
```

One chunk = one focused session. Don't combine chunks — they're scoped to stay under context limits and produce clean commits.
