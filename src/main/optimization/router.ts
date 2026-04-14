/**
 * Vulnerability-Aware Agent Router
 *
 * Full model roster across providers — each model has specific strengths.
 * The router classifies each vulnerability and picks the best specialist,
 * spreading work across many different agents.
 *
 * Provider lineup:
 *   Anthropic  → Claude Opus 4 (apex reasoning), Claude Sonnet 4.6 (fast security), Haiku 4.5 (cheap triage)
 *   OpenAI     → GPT-5.4 (broad knowledge), GPT-4.1 (config/infra), o3 (deep chain-of-thought)
 *   Google     → Gemini 2.5 Pro (multi-file analysis), Gemini 2.5 Flash (free tests/docs)
 *   DeepSeek   → DeepSeek V3 (cheap code), DeepSeek R1 (reasoning)
 *   Meta       → Llama 4 Maverick (free via Ollama)
 *   Mistral    → Codestral (fast code edits)
 *   Qwen       → Qwen3 235B (multilingual/polyglot deps)
 */

import type { Vulnerability } from '../engine/types'

// ── Vuln task types the classifier can assign ───────────────────────────

export type VulnTaskType =
  | 'critical-exploit'      // known exploit / KEV — apex model, zero tolerance
  | 'breaking-upgrade'      // major version bump with breaking API changes
  | 'security-refactor'     // code-level security fix (injection, XSS, RCE, etc.)
  | 'multi-service-patch'   // vuln spans multiple services — needs broad context
  | 'config-hardening'      // config / infra change (TLS, headers, CORS, etc.)
  | 'dependency-bump'       // simple semver bump, no breaking changes
  | 'compliance-patch'      // compliance-deadline-driven, needs accuracy + audit trail
  | 'lockfile-regen'        // just regenerate lockfile / checksum
  | 'test-generation'       // generate regression tests for the patched vuln
  | 'deep-analysis'         // complex reasoning needed (chained vulns, transitive deps)

// ── Model capabilities ─────────────────────────────────────────────────

export interface ModelCapability {
  model: string
  displayName: string
  provider: string
  costPer1kTokens: number
  maxComplexity: 'low' | 'medium' | 'high'
  strengths: VulnTaskType[]
  available: boolean
}

export const DEFAULT_MODELS: ModelCapability[] = [
  // ═══ FREE / LOCAL ═══════════════════════════════════════════════════

  {
    model: 'ollama/llama4-maverick',
    displayName: 'Llama 4 Maverick',
    provider: 'Ollama (local)',
    costPer1kTokens: 0,
    maxComplexity: 'medium',
    strengths: ['lockfile-regen', 'dependency-bump'],
    available: false // checked at runtime
  },
  {
    model: 'google/gemini-2.5-flash',
    displayName: 'Gemini 2.5 Flash',
    provider: 'Google',
    costPer1kTokens: 0,
    maxComplexity: 'medium',
    strengths: ['test-generation', 'dependency-bump', 'lockfile-regen'],
    available: true
  },

  // ═══ BUDGET ═════════════════════════════════════════════════════════

  {
    model: 'anthropic/claude-haiku-4.5',
    displayName: 'Claude Haiku 4.5',
    provider: 'Anthropic',
    costPer1kTokens: 0.0005,
    maxComplexity: 'medium',
    strengths: ['dependency-bump', 'lockfile-regen', 'test-generation'],
    available: true
  },
  {
    model: 'mistral/codestral-latest',
    displayName: 'Codestral',
    provider: 'Mistral',
    costPer1kTokens: 0.0008,
    maxComplexity: 'medium',
    strengths: ['dependency-bump', 'config-hardening', 'lockfile-regen'],
    available: true
  },
  {
    model: 'deepseek/deepseek-chat',
    displayName: 'DeepSeek V3',
    provider: 'DeepSeek',
    costPer1kTokens: 0.001,
    maxComplexity: 'medium',
    strengths: ['dependency-bump', 'lockfile-regen', 'config-hardening'],
    available: true
  },

  // ═══ MID-TIER ═══════════════════════════════════════════════════════

  {
    model: 'qwen/qwen3-235b',
    displayName: 'Qwen3 235B',
    provider: 'Qwen',
    costPer1kTokens: 0.0015,
    maxComplexity: 'high',
    strengths: ['dependency-bump', 'config-hardening', 'multi-service-patch'],
    available: true
  },
  {
    model: 'google/gemini-2.5-pro',
    displayName: 'Gemini 2.5 Pro',
    provider: 'Google',
    costPer1kTokens: 0.002,
    maxComplexity: 'high',
    strengths: ['multi-service-patch', 'breaking-upgrade', 'deep-analysis'],
    available: true
  },
  {
    model: 'deepseek/deepseek-r1',
    displayName: 'DeepSeek R1',
    provider: 'DeepSeek',
    costPer1kTokens: 0.002,
    maxComplexity: 'high',
    strengths: ['deep-analysis', 'security-refactor', 'breaking-upgrade'],
    available: true
  },

  // ═══ PREMIUM ════════════════════════════════════════════════════════

  {
    model: 'anthropic/claude-sonnet-4.6',
    displayName: 'Claude Sonnet 4.6',
    provider: 'Anthropic',
    costPer1kTokens: 0.003,
    maxComplexity: 'high',
    strengths: ['security-refactor', 'breaking-upgrade', 'compliance-patch', 'critical-exploit'],
    available: true
  },
  {
    model: 'openai/gpt-4.1',
    displayName: 'GPT-4.1',
    provider: 'OpenAI',
    costPer1kTokens: 0.003,
    maxComplexity: 'high',
    strengths: ['config-hardening', 'compliance-patch', 'multi-service-patch'],
    available: true
  },
  {
    model: 'openai/gpt-5.4',
    displayName: 'GPT-5.4',
    provider: 'OpenAI',
    costPer1kTokens: 0.005,
    maxComplexity: 'high',
    strengths: ['breaking-upgrade', 'compliance-patch', 'security-refactor', 'config-hardening'],
    available: true
  },

  // ═══ APEX (heaviest reasoning) ══════════════════════════════════════

  {
    model: 'openai/o3',
    displayName: 'o3',
    provider: 'OpenAI',
    costPer1kTokens: 0.01,
    maxComplexity: 'high',
    strengths: ['deep-analysis', 'critical-exploit', 'multi-service-patch'],
    available: true
  },
  {
    model: 'anthropic/claude-opus-4',
    displayName: 'Claude Opus 4',
    provider: 'Anthropic',
    costPer1kTokens: 0.015,
    maxComplexity: 'high',
    strengths: ['critical-exploit', 'security-refactor', 'deep-analysis', 'multi-service-patch', 'breaking-upgrade'],
    available: true
  }
]

// ── Vulnerability classifier ────────────────────────────────────────────

export function classifyVuln(vuln: Pick<Vulnerability, 'severity' | 'cvssScore' | 'epssScore' | 'knownExploit' | 'inKev' | 'hasPublicExploit' | 'attackVector' | 'complexity' | 'complianceViolations' | 'complianceDeadlineDays' | 'affectedPackage' | 'patchedVersion' | 'description' | 'affectedServiceIds'>): VulnTaskType {
  const descLower = vuln.description.toLowerCase()

  // 1. Active exploits → apex model, zero tolerance
  if (vuln.knownExploit || vuln.inKev || vuln.hasPublicExploit) {
    // If it also spans multiple services, flag that too
    if (vuln.affectedServiceIds.length >= 3) return 'critical-exploit' // still critical, but router will pick Opus
    return 'critical-exploit'
  }

  // 2. Compliance deadline within 30 days → needs accuracy + audit reasoning
  if (vuln.complianceViolations.length > 0 && vuln.complianceDeadlineDays !== null && vuln.complianceDeadlineDays <= 30) {
    return 'compliance-patch'
  }

  // 3. Multi-service blast radius — vuln touches 3+ services
  if (vuln.affectedServiceIds.length >= 3) {
    return 'multi-service-patch'
  }

  // 4. Detect major version bumps (breaking changes likely)
  const currentVer = vuln.affectedPackage.split('@').pop() ?? ''
  const patchedVer = vuln.patchedVersion?.split('@').pop() ?? ''
  const currentMajor = parseInt(currentVer.split('.')[0], 10)
  const patchedMajor = parseInt(patchedVer.split('.')[0], 10)
  if (!isNaN(currentMajor) && !isNaN(patchedMajor) && patchedMajor > currentMajor) {
    return 'breaking-upgrade'
  }

  // 5. Deep analysis — chained/transitive vulns, complex attack vectors
  const chainPatterns = ['chained', 'transitive', 'indirect dependency', 'supply chain', 'dependency confusion']
  if (chainPatterns.some(p => descLower.includes(p)) || (vuln.cvssScore >= 8.0 && vuln.complexity === 'high')) {
    return 'deep-analysis'
  }

  // 6. Code-level security issues (not just a dep bump)
  const codePatterns = ['injection', 'xss', 'rce', 'remote code', 'deserialization', 'prototype pollution',
    'path traversal', 'ssrf', 'command injection', 'buffer overflow', 'arbitrary code', 'sql injection',
    'nosql', 'ldap injection', 'xml injection', 'xxe', 'insecure deserialization']
  if (vuln.severity === 'critical' || (vuln.cvssScore >= 9.0 && codePatterns.some(p => descLower.includes(p)))) {
    return 'security-refactor'
  }

  // 7. Config / infra issues
  const configPatterns = ['tls', 'ssl', 'cors', 'header', 'csp', 'hsts', 'certificate', 'cipher',
    'permission', 'misconfigur', 'default credential', 'exposed port', 'open redirect']
  if (configPatterns.some(p => descLower.includes(p))) {
    return 'config-hardening'
  }

  // 8. High severity + high EPSS → still needs a strong model
  if (vuln.cvssScore >= 7.0 && vuln.epssScore >= 0.3) {
    return 'security-refactor'
  }

  // 9. Simple dependency bump (minor/patch version, low-medium severity)
  if (vuln.complexity === 'low' || (vuln.complexity === 'medium' && vuln.cvssScore < 7.0)) {
    return 'dependency-bump'
  }

  // Default: security refactor to be safe
  return 'security-refactor'
}

// ── Router ──────────────────────────────────────────────────────────────

const COMPLEXITY_ORDER = { low: 0, medium: 1, high: 2 }

export class ModelRouter {
  private models: ModelCapability[] = [...DEFAULT_MODELS]
  private ollamaAvailable = false

  setOllamaAvailable(available: boolean) {
    this.ollamaAvailable = available
    for (const m of this.models) {
      if (m.model.startsWith('ollama/')) {
        m.available = available
      }
    }
  }

  /**
   * Classify a vulnerability and route to the best model for that task type.
   */
  routeVuln(vuln: Parameters<typeof classifyVuln>[0]): { model: string; displayName: string; provider: string; taskType: VulnTaskType; reasoning: string } {
    const taskType = classifyVuln(vuln)
    const model = this.routeByTaskType(taskType, vuln.complexity)
    const cap = this.models.find(m => m.model === model)

    return {
      model,
      displayName: cap?.displayName ?? model.split('/').pop() ?? model,
      provider: cap?.provider ?? 'unknown',
      taskType,
      reasoning: this.explainRouting(taskType, model, vuln)
    }
  }

  /**
   * Route by explicit task type + complexity.
   * Prefers models whose strengths include this task type.
   * For critical tasks → most capable first. For simple tasks → cheapest first.
   */
  routeByTaskType(taskType: VulnTaskType, complexity: 'low' | 'medium' | 'high'): string {
    const available = this.models.filter(m => m.available)
    const capable = available.filter(m => COMPLEXITY_ORDER[m.maxComplexity] >= COMPLEXITY_ORDER[complexity])

    const criticalTypes: VulnTaskType[] = ['critical-exploit', 'breaking-upgrade', 'security-refactor', 'compliance-patch', 'deep-analysis', 'multi-service-patch']
    const isCritical = criticalTypes.includes(taskType)

    // Prefer specialist models for this task type
    const specialists = capable
      .filter(m => m.strengths.includes(taskType))
      .sort((a, b) => {
        if (isCritical) return b.costPer1kTokens - a.costPer1kTokens // most capable first
        return a.costPer1kTokens - b.costPer1kTokens // cheapest first
      })

    if (specialists.length > 0) return specialists[0].model

    // No specialist — fall back to cheapest capable model
    const fallback = capable.sort((a, b) => a.costPer1kTokens - b.costPer1kTokens)
    return fallback[0]?.model ?? 'anthropic/claude-sonnet-4.6'
  }

  /**
   * Legacy route method — still works for non-vuln tasks.
   */
  route(taskType: string, complexity: 'low' | 'medium' | 'high'): string {
    const mapped = this.mapLegacyTaskType(taskType)
    return this.routeByTaskType(mapped, complexity)
  }

  private mapLegacyTaskType(taskType: string): VulnTaskType {
    switch (taskType) {
      case 'security': return 'security-refactor'
      case 'config': return 'config-hardening'
      case 'test': return 'test-generation'
      case 'docs': return 'test-generation'
      case 'css': return 'dependency-bump'
      default: return 'dependency-bump'
    }
  }

  private explainRouting(taskType: VulnTaskType, model: string, vuln: Parameters<typeof classifyVuln>[0]): string {
    const cap = this.models.find(m => m.model === model)
    const name = cap ? `${cap.displayName} (${cap.provider})` : model
    switch (taskType) {
      case 'critical-exploit':
        return `${name}: active exploit${vuln.inKev ? ' (CISA KEV)' : vuln.hasPublicExploit ? ' (public PoC)' : ''} — apex-tier model, zero tolerance`
      case 'breaking-upgrade':
        return `${name}: major version bump — needs API migration + breaking change expertise`
      case 'security-refactor':
        return `${name}: code-level security fix (CVSS ${vuln.cvssScore}) — needs security reasoning`
      case 'multi-service-patch':
        return `${name}: blast radius across ${vuln.affectedServiceIds.length} services — needs broad context window`
      case 'deep-analysis':
        return `${name}: complex dependency chain — needs deep chain-of-thought reasoning`
      case 'compliance-patch':
        return `${name}: compliance deadline in ${vuln.complianceDeadlineDays}d — needs accuracy + audit trail`
      case 'config-hardening':
        return `${name}: infrastructure/config hardening`
      case 'dependency-bump':
        return `${name}: simple version bump — cost-efficient model`
      case 'lockfile-regen':
        return `${name}: lockfile regeneration — minimal model`
      case 'test-generation':
        return `${name}: generating regression tests`
    }
  }

  estimateCost(model: string, complexity: 'low' | 'medium' | 'high'): number {
    const capability = this.models.find((m) => m.model === model)
    if (!capability) return 0
    const tokenEstimates = { low: 2000, medium: 8000, high: 20000 }
    return (tokenEstimates[complexity] / 1000) * capability.costPer1kTokens
  }

  getModels(): ModelCapability[] {
    return [...this.models]
  }

  getModelByName(model: string): ModelCapability | undefined {
    return this.models.find(m => m.model === model)
  }

  getSavings(taskType: string, complexity: 'low' | 'medium' | 'high'): { routed: string; routedCost: number; defaultCost: number; saved: number } {
    const routed = this.route(taskType, complexity)
    const routedCost = this.estimateCost(routed, complexity)
    const defaultCost = this.estimateCost('anthropic/claude-sonnet-4.6', complexity)
    return { routed, routedCost, defaultCost, saved: defaultCost - routedCost }
  }
}

export const modelRouter = new ModelRouter()
