# FAVR Agent Roster

## Why Not Just Use One Model?

Most vulnerability scanners either sort by CVSS and tell you to "patch everything" or run every fix through the same LLM. Both approaches waste money and produce worse results. A critical RCE with a public exploit needs a fundamentally different kind of reasoning than bumping `lodash` from 4.17.20 to 4.17.21.

FAVR classifies each vulnerability by its risk profile and routes it to the model whose architecture and training make it the best fit — not just the cheapest or most expensive. The result: better patches, lower cost, and a visible audit trail of *why* each agent was chosen.

---

## The Roster

### Free / Local

| Model | Provider | Cost | Strengths | Why This Model |
|-------|----------|------|-----------|----------------|
| **Llama 4 Maverick** | Ollama (local) | $0 | Lockfile regen, simple dep bumps | Runs entirely on the user's machine — zero cost, zero latency, zero data leaving the network. For trivial tasks like regenerating a lockfile after a version pin, there's no reason to pay for a cloud model. Also the right choice when the codebase is under NDA or contains secrets. |
| **Gemini 2.5 Flash** | Google | $0 | Test generation, dep bumps, lockfiles | Google's free tier is genuinely capable for structured output tasks. Generating regression tests for a patched CVE is mostly templating + understanding the fix diff — Flash handles this well and costs nothing. |

### Budget Tier

| Model | Provider | Cost/1K tokens | Strengths | Why This Model |
|-------|----------|---------------|-----------|----------------|
| **Claude Haiku 4.5** | Anthropic | $0.0005 | Dep bumps, lockfiles, test gen | Anthropic's smallest model still follows instructions precisely. For "change version X to Y in package.json" tasks, Haiku's instruction-following is better than similarly-priced alternatives, and it inherits Anthropic's safety training — important when you're writing to a user's codebase. |
| **Codestral** | Mistral | $0.0008 | Dep bumps, config hardening | Mistral's code-specialized model. Trained specifically on code editing tasks, so it produces cleaner diffs with fewer hallucinated changes than general-purpose models at this price point. Good for config file edits (nginx, docker-compose, CI configs). |
| **DeepSeek V3** | DeepSeek | $0.001 | Dep bumps, lockfiles, config | Strong coding model at rock-bottom pricing. Handles straightforward version bumps and config changes reliably. We cap it at medium complexity — it starts to struggle with multi-file refactors and nuanced security reasoning. |

### Mid-Tier

| Model | Provider | Cost/1K tokens | Strengths | Why This Model |
|-------|----------|---------------|-----------|----------------|
| **Qwen3 235B** | Qwen | $0.0015 | Config hardening, multi-service patches, dep bumps | Excellent multilingual and polyglot support — handles projects with mixed ecosystems (Python + Go + JS in a monorepo) better than most Western models. The 235B parameter count gives it enough reasoning depth for cross-service dependency analysis. |
| **Gemini 2.5 Pro** | Google | $0.002 | Multi-service patches, breaking upgrades, deep analysis | Google's 1M+ context window is the key differentiator. When a vulnerability spans 3+ services and the model needs to see multiple package manifests, import chains, and API surfaces simultaneously, Gemini Pro can hold it all in context without summarization loss. |
| **DeepSeek R1** | DeepSeek | $0.002 | Deep analysis, security refactors, breaking upgrades | DeepSeek's reasoning model — it "thinks out loud" with chain-of-thought before producing code. For chained/transitive vulnerabilities where you need to trace an exploit path through multiple dependency layers, R1's explicit reasoning catches issues that faster models miss. |

### Premium

| Model | Provider | Cost/1K tokens | Strengths | Why This Model |
|-------|----------|---------------|-----------|----------------|
| **Claude Sonnet 4.6** | Anthropic | $0.003 | Security refactors, breaking upgrades, compliance, critical exploits | The workhorse for serious security work. Sonnet's instruction-following is near-perfect, it rarely hallucinates file paths or function names, and it understands security concepts deeply (OWASP categories, CWE mappings, exploit mechanics). For a vulnerability that requires rewriting code — not just bumping a version — Sonnet produces patches that actually compile and address the root cause. |
| **GPT-4.1** | OpenAI | $0.003 | Config hardening, compliance, multi-service patches | OpenAI's latest production model has exceptional breadth of infrastructure knowledge — Kubernetes configs, Terraform, CI/CD pipelines, cloud IAM policies. When a CVE fix requires changing infrastructure config rather than application code, GPT-4.1's training data gives it an edge. Also strong for compliance patches where the fix needs to align with specific framework requirements (PCI-DSS, HIPAA, SOC2). |
| **GPT-5.4** | OpenAI | $0.005 | Breaking upgrades, compliance, security refactors, config | The most broadly capable OpenAI model. Reserved for cases where a breaking upgrade requires understanding both the old and new API surfaces deeply, or where a compliance patch needs careful reasoning about regulatory requirements. More expensive, so only routed here when cheaper models' strengths don't match. |

### Apex (Heaviest Reasoning)

| Model | Provider | Cost/1K tokens | Strengths | Why This Model |
|-------|----------|---------------|-----------|----------------|
| **o3** | OpenAI | $0.01 | Deep analysis, critical exploits, multi-service patches | OpenAI's dedicated reasoning model. Uses extended chain-of-thought internally before producing output. For vulnerabilities that involve complex dependency chains, transitive exploit paths, or supply chain attacks, o3 can trace the full attack graph and produce fixes that account for indirect effects. Expensive, so only used when the classifier detects chained vulns or high-complexity critical issues. |
| **Claude Opus 4** | Anthropic | $0.015 | Critical exploits, security refactors, deep analysis, multi-service, breaking upgrades | The apex model. Opus is deployed *only* when there is a known exploit in the wild, the CVE is in CISA's KEV catalog, or a public proof-of-concept exists. When an attacker could be actively exploiting this vulnerability *right now*, you don't optimize for cost — you optimize for correctness. Opus has the deepest reasoning capability and the strongest security understanding of any model in the roster. It also handles multi-service blast radius better than any other model because it can hold complex system architectures in working memory. |

---

## How Classification Works

Each vulnerability is classified before routing. The classifier examines these signals:

| Signal | What It Tells Us | Classification Impact |
|--------|-----------------|----------------------|
| `knownExploit`, `inKev`, `hasPublicExploit` | Active threat — someone can attack this *today* | → `critical-exploit` (always Opus) |
| `complianceViolations` + deadline ≤ 30 days | Regulatory urgency — failing audit if unpatched | → `compliance-patch` (GPT-5.4 or Sonnet) |
| `affectedServiceIds.length >= 3` | Wide blast radius across the system | → `multi-service-patch` (Opus, o3, or Gemini Pro) |
| Major version bump detected | Breaking API changes likely | → `breaking-upgrade` (Sonnet, GPT-5.4, or R1) |
| Description matches chain/transitive patterns | Complex dependency chain analysis needed | → `deep-analysis` (o3, Opus, or R1) |
| Description matches injection/RCE/XSS patterns | Code-level security fix required | → `security-refactor` (Sonnet or Opus) |
| Description matches TLS/CORS/config patterns | Infrastructure config change | → `config-hardening` (GPT-4.1 or Codestral) |
| CVSS ≥ 7.0 + EPSS ≥ 0.3 | High severity with real exploit probability | → `security-refactor` |
| Low complexity or medium + CVSS < 7.0 | Simple version bump | → `dependency-bump` (DeepSeek, Haiku, or Gemini Flash) |

### Routing Priority

For **critical task types** (critical-exploit, security-refactor, breaking-upgrade, compliance-patch, deep-analysis, multi-service-patch), the router picks the **most capable** model whose strengths match — cost is secondary to correctness.

For **simple task types** (dependency-bump, lockfile-regen, config-hardening, test-generation), the router picks the **cheapest** capable model — no need to spend $0.015/1K tokens on a lockfile regen.

This means a single Quick Fix run across 15 vulnerabilities might use 6-8 different models, each chosen for a specific reason.

---

## Example Routing (Meridian Financial Demo)

| CVE | Vulnerability | Classification | Agent | Why |
|-----|--------------|---------------|-------|-----|
| CVE-2024-29041 | Express.js path traversal | `security-refactor` | Claude Sonnet 4.6 | Code-level path traversal fix, CVSS 7.5 |
| CVE-2024-28849 | follow-redirects SSRF | `critical-exploit` | Claude Opus 4 | Known public exploit |
| CVE-2023-26159 | follow-redirects open redirect | `config-hardening` | GPT-4.1 | Redirect/config issue |
| CVE-2024-39338 | Axios SSRF | `security-refactor` | Claude Sonnet 4.6 | SSRF is a code-level security pattern |
| CVE-2024-55565 | nanoid predictability | `dependency-bump` | DeepSeek V3 | Simple version bump, medium severity |
| CVE-2023-44270 | PostCSS line break parsing | `dependency-bump` | Claude Haiku 4.5 | Low severity, trivial fix |
| CVE-2024-47764 | cookie signature bypass | `breaking-upgrade` | Claude Sonnet 4.6 | Major version bump (v0.6→v1.0) |
| CVE-2024-4068 | braces ReDoS | `dependency-bump` | Gemini 2.5 Flash | Low severity, free model |
| CVE-2024-43788 | Webpack XSS | `security-refactor` | Claude Sonnet 4.6 | XSS pattern detected |

---

## Design Decisions

**Why not just use Claude Opus for everything?**
Cost. A full scan of 15 vulnerabilities at Opus pricing would cost ~$4.50. With intelligent routing, the same scan costs ~$0.80 — 82% cheaper — because 60% of vulns are simple version bumps that Haiku or DeepSeek handle perfectly.

**Why not just use the cheapest model for everything?**
Correctness. DeepSeek V3 can bump a version number, but it will hallucinate when asked to refactor a deserialization vulnerability or migrate a breaking API change. The cost of a bad security patch (false sense of security, broken build, or worse — introducing a new vulnerability) far outweighs the $0.03 saved by using a cheaper model.

**Why include reasoning models (o3, R1)?**
Some vulnerabilities can't be fixed by pattern matching. Transitive dependency chains, supply chain attacks, and chained exploits require the model to *think* — to trace an attack path through multiple layers. Standard LLMs generate code immediately; reasoning models spend compute on analysis first. This matters when the wrong fix could break 3 downstream services.

**Why Gemini Pro for multi-service patches?**
Context window. When a vuln affects 5 services, the model needs to see all 5 package manifests, their import chains, and potentially their deployment configs simultaneously. Gemini Pro's 1M+ token context handles this without chunking or summarization, which means fewer missed side effects.

**Why separate GPT-4.1 from GPT-5.4?**
Different specializations. GPT-4.1 has stronger infrastructure/config knowledge (it was likely trained on more DevOps data), while GPT-5.4 is the stronger general reasoner. Using both means infra fixes go to the infra specialist and code fixes go to the code specialist.
