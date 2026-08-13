# FAVR — Find, Analyze, Verify, Resolve

Security teams drown in CVE alerts but lack a principled way to decide *what to patch first*. FAVR ingests a real codebase, discovers its services and dependencies, queries live CVE databases, and produces a mathematically optimal patching plan — combining Bayesian risk propagation, Monte Carlo simulation, and Pareto optimization so engineers fix the highest-impact vulnerabilities first.

> **Note:** This is a fork of a team project. See the [upstream repo](https://github.com/gvenu06/FAVR) for the original. My contributions include the Python agent pipeline (`favr/`), ML vulnerability classifier and patch-priority predictor (`favr/optimization/`), training scripts (`scripts/`), and the FastAPI server (`favr/pipeline/server.py`).

## Tech Stack

| Layer | Technologies |
|---|---|
| **Analysis engine** | TypeScript · attack-graph construction · Bayesian belief propagation · Monte Carlo simulation (configurable iterations) · Pareto frontier optimization · EPSS scoring · blast-radius analysis |
| **CLI** | TypeScript · Commander.js · output formatters (table, JSON, HTML, SARIF) · `.favr.yml` config · diff mode for PR scanning |
| **Desktop app** | Electron · React 18 · Zustand · Tailwind CSS · Recharts · D3 dependency graph · Vite |
| **Python agent pipeline** | FastAPI · Anthropic SDK (Claude) · scikit-learn (GradientBoosting classifier + regressor) · NumPy · Pydantic |
| **Backend** | Supabase (Postgres, Edge Functions, Auth) · Stripe integration |
| **CI/CD** | GitHub Actions (SARIF upload to Code Scanning) · GitLab CI (MR notes) |

---

## How It Works

### TypeScript Analysis Engine (`packages/favr-core`)

A headless library with zero Electron dependencies, usable from CLI or desktop app:

1. **Codebase discovery** — walks the project tree, identifies services, parses lockfiles, maps dependency graphs
2. **CVE lookup** — queries OSV.dev for known vulnerabilities against discovered packages
3. **Attack-graph construction** — models how vulnerabilities propagate through service dependencies
4. **Bayesian risk propagation** — computes posterior risk scores per service given the dependency graph
5. **Monte Carlo simulation** — samples thousands of patch orderings to find the sequence that minimizes cumulative risk exposure
6. **Pareto optimization** — generates cost-vs-risk trade-off profiles so teams can pick a strategy that fits their budget
7. **Report generation** — outputs HTML, JSON, SARIF, or terminal table

### Python Agent Pipeline (`favr/`)

A multi-agent system that adds LLM-powered reasoning on top of the numerical engine:

- **Orchestrator** coordinates 5 specialist agents (scanner, dependency-conflict, remediation, compliance, risk-assessment) via a message bus
- **Vulnerability classifier** — a scikit-learn GradientBoosting model trained to classify CVEs into 10 task types (critical-exploit, breaking-upgrade, config-hardening, etc.) based on CVSS features and description keywords
- **Patch priority predictor** — a GradientBoosting regressor trained on Monte Carlo simulation outputs to predict optimal patch ordering without the full simulation cost
- **FastAPI server** exposes the full pipeline as a REST API (`/api/pipeline/run`, `/api/vulnerabilities`, `/api/plan`, `/api/monte-carlo/results`, etc.)

### Desktop App (`src/`)

An Electron app that wraps the analysis engine with an interactive UI:

- Dashboard with agent cards showing real-time pipeline progress
- Remediation workspace with what-if analysis and schedule planning
- Monte Carlo visualization, Pareto frontier charts, dependency graphs, service heatmaps
- Git safety system — branches per task, stash management, merge-on-approve
- LLM-powered validation pipeline with Gemini Flash VLM for screenshot-based verification
- Free-first model routing (Ollama → Gemini → DeepSeek → Claude → GPT)

---

## Quick Start

### Desktop App

```bash
npm install
npm run dev          # Opens the Electron app
```

### CLI (local development)

```bash
# Build the workspace packages
cd packages/favr-core && npm run build && cd ../..
cd packages/favr-cli && npm run build && cd ../..

# Run from the workspace
npx favr-scan ./your-project

# Output formats
npx favr-scan ./your-project --format json
npx favr-scan ./your-project --format sarif --output results.sarif
npx favr-scan ./your-project --format html --output report.html

# Fail CI if any critical or high findings
npx favr-scan ./your-project --threshold high

# Diff mode — only new or worsened vulnerabilities (useful in PRs)
npx favr-scan ./your-project --diff --threshold high
```

### Python Pipeline

```bash
pip install -r requirements.txt
python -m favr.pipeline          # Runs the agent pipeline on synthetic data
uvicorn favr.pipeline.server:app --reload   # Starts the FastAPI server on :8000
```

---

## CI/CD Integration

Copy the included workflow files into your repo:

- **GitHub Actions** — `.github/workflows/favr-scan.yml` runs on PRs, uploads SARIF to GitHub Code Scanning, posts a summary comment, and fails the check on threshold violations.
- **GitLab CI** — `.gitlab-ci.yml` runs on merge requests, posts findings as MR notes, and fails on threshold violations.

### Config File (`.favr.yml`)

```yaml
threshold: high
ignoredCves:
  - CVE-2024-0001
iterations: 500
complianceStandards:
  - PCI-DSS
```

---

## Project Structure

```
packages/
├── favr-core/           # Headless analysis engine (zero Electron deps)
│   └── src/
│       ├── index.ts     # scan() entry point
│       ├── engine/      # Attack graph, Bayesian, Monte Carlo, Pareto, scheduler
│       └── ingest/      # Codebase analyzer, CVE lookup, scan history
├── favr-cli/            # CLI tool (favr-scan)
│   └── src/
│       ├── index.ts     # CLI entry point (Commander)
│       ├── formatters/  # table, json, html, sarif
│       └── config.ts    # .favr.yml loader
favr/                    # Python agent pipeline
├── agents/              # Orchestrator + 5 specialist agents
├── optimization/        # Bayesian, Monte Carlo, Pareto, ML classifier, ML predictor
└── pipeline/            # FastAPI server + CLI entry point
src/                     # Electron desktop app
├── main/                # Main process (IPC, engine, validation, git safety)
├── renderer/            # React UI (dashboard, charts, settings, workspace)
└── preload/             # Context bridge
scripts/                 # ML model training scripts
supabase/                # Edge functions (chat proxy, credits, validation)
```

---

## Tests

```bash
cd packages/favr-cli
npm test                 # Runs Vitest suite (config, formatters, diff, threshold, e2e)
```

---

## License

[MIT](./LICENSE)
