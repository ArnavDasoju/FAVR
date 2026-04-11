# FAVR

**Flexible Attack Vector Risk** — scan any real codebase and get a mathematically optimal patching plan.

Point it at a project directory → it auto-discovers services, maps dependencies, queries real CVE databases, then runs a full analysis pipeline (Bayesian risk propagation, Monte Carlo simulation, Pareto optimization) to produce an optimal patching strategy.

## Quick Start

```bash
# Desktop app
npm run dev

# CLI
npx favr-scan ./your-project
```

## CI/CD Integration

Get FAVR scanning your pull requests in under 5 minutes.

### 1. Install

```bash
npm install -g @favr/cli
# or use npx: npx favr-scan ...
```

### 2. Add a config file (optional)

Create `.favr.yml` in your project root:

```yaml
threshold: high
ignoredCves:
  - CVE-2024-0001   # accepted risk, tracked in JIRA-1234
iterations: 500
```

### 3. Drop in the workflow file

**GitHub Actions** — copy `.github/workflows/favr-scan.yml` from this repo into yours. It will:
- Run on every pull request
- Upload SARIF results to GitHub Code Scanning (Security tab)
- Post a comment on the PR with a summary
- Fail the check if any finding meets or exceeds `--threshold high`

**GitLab CI** — copy `.gitlab-ci.yml` from this repo. It will:
- Run on merge requests
- Post a note on the MR with findings
- Fail the pipeline on threshold violations

### CLI Usage

```bash
# Scan with colored table output (default)
favr-scan ./my-project

# JSON output (pipe-friendly, nothing else on stdout)
favr-scan ./my-project --format json

# SARIF for code scanning integrations
favr-scan ./my-project --format sarif --output results.sarif

# HTML report
favr-scan ./my-project --format html --output report.html

# Fail CI if any critical or high vulns found
favr-scan ./my-project --threshold high

# Diff mode — only report new or worsened vulns (great for PRs)
favr-scan ./my-project --diff --threshold high

# Use a CVSS score as threshold
favr-scan ./my-project --threshold 7.0

# Custom config file
favr-scan ./my-project --config security/favr-config.yml
```

### Config File Reference

Supported formats: `.favr.yml`, `.favr.yaml`, `.favr.json`

| Key | Type | Description |
|-----|------|-------------|
| `threshold` | `string` | Severity (`low`/`medium`/`high`/`critical`) or CVSS score |
| `ignoredCves` | `string[]` | CVE IDs to exclude from results |
| `patchingCosts` | `object` | Override remediation cost per CVE ID |
| `iterations` | `number` | Monte Carlo simulation iterations (default: 500) |
| `complianceStandards` | `string[]` | Compliance frameworks to check |

CLI flags override config file values.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no findings above threshold |
| `1` | Findings at or above threshold (or new/worsened in diff mode) |
| `2` | Error (bad config, scan failure, invalid arguments) |

## Project Structure

```
packages/
├── favr-core/          # Headless analysis engine (zero Electron deps)
│   └── src/
│       ├── index.ts    # scan() entry point
│       ├── engine/     # Attack graph, Bayesian, Monte Carlo, Pareto, etc.
│       └── ingest/     # Codebase analyzer, CVE lookup, scan history
├── favr-cli/           # CLI binary (favr-scan)
│   └── src/
│       ├── index.ts    # CLI entry point (commander)
│       ├── formatters/ # table, json, html, sarif
│       ├── config.ts   # .favr.yml loader
│       └── diff.ts     # Diff mode logic
src/                    # Electron desktop app (consumes @favr/core)
```

## Development

```bash
npm install          # Install all workspace dependencies
npm run dev          # Start Electron desktop app
npm run build        # Build desktop app

# CLI development
cd packages/favr-cli
npm run build        # Compile TypeScript
npm test             # Run tests

# Core engine
cd packages/favr-core
npm run build        # Compile TypeScript
```
