/**
 * Agent Stats Tracker — persists per-model performance history using electron-store.
 *
 * Records success/failure, cost, tokens, and duration for every agent fix attempt.
 * Aggregated stats feed into the budget optimizer for data-driven model selection.
 */

import Store from 'electron-store'

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

export interface AgentStats {
  model: string
  successRate: number
  avgCostPerFix: number
  avgTokensPerFix: number
  avgDurationMs: number
  totalAttempts: number
  totalSuccesses: number
  complexityScores: {
    low: number
    medium: number
    high: number
  }
  taskTypeScores: Record<string, number>
}

interface StatsStoreSchema {
  history: ModelHistoryEntry[]
}

const statsStore = new Store<StatsStoreSchema>({
  name: 'bld-agent-stats',
  defaults: {
    history: []
  }
})

// Default stats for models that have no history yet.
// These are reasonable priors — the optimizer falls back to these
// until real data accumulates.
const DEFAULT_STATS: Record<string, Omit<AgentStats, 'model'>> = {
  'anthropic/claude-sonnet-4.6': {
    successRate: 0.85,
    avgCostPerFix: 0.08,
    avgTokensPerFix: 4000,
    avgDurationMs: 15000,
    totalAttempts: 0,
    totalSuccesses: 0,
    complexityScores: { low: 0.95, medium: 0.88, high: 0.75 },
    taskTypeScores: {}
  },
  'openai/gpt-5.4': {
    successRate: 0.80,
    avgCostPerFix: 0.12,
    avgTokensPerFix: 5000,
    avgDurationMs: 18000,
    totalAttempts: 0,
    totalSuccesses: 0,
    complexityScores: { low: 0.92, medium: 0.82, high: 0.70 },
    taskTypeScores: {}
  },
  'deepseek/deepseek-chat': {
    successRate: 0.70,
    avgCostPerFix: 0.003,
    avgTokensPerFix: 3500,
    avgDurationMs: 12000,
    totalAttempts: 0,
    totalSuccesses: 0,
    complexityScores: { low: 0.85, medium: 0.72, high: 0.50 },
    taskTypeScores: {}
  },
  'google/gemini-2.5-flash': {
    successRate: 0.60,
    avgCostPerFix: 0.001,
    avgTokensPerFix: 2500,
    avgDurationMs: 8000,
    totalAttempts: 0,
    totalSuccesses: 0,
    complexityScores: { low: 0.80, medium: 0.58, high: 0.35 },
    taskTypeScores: {}
  },
  'ollama/llama3': {
    successRate: 0.50,
    avgCostPerFix: 0,
    avgTokensPerFix: 2000,
    avgDurationMs: 20000,
    totalAttempts: 0,
    totalSuccesses: 0,
    complexityScores: { low: 0.70, medium: 0.45, high: 0.25 },
    taskTypeScores: {}
  }
}

class AgentStatsTracker {
  /**
   * Record a completed fix attempt.
   */
  record(entry: ModelHistoryEntry): void {
    const history = statsStore.get('history')
    history.push(entry)
    // Keep last 500 entries to avoid unbounded growth
    if (history.length > 500) {
      statsStore.set('history', history.slice(-500))
    } else {
      statsStore.set('history', history)
    }
  }

  /**
   * Get aggregated stats for a single model.
   * Blends real history with default priors using Bayesian-style weighting:
   * more history = less reliance on defaults.
   */
  getStats(model: string): AgentStats {
    const history = statsStore.get('history').filter(e => e.model === model)
    const defaults = DEFAULT_STATS[model]

    if (history.length === 0 && defaults) {
      return { model, ...defaults }
    }

    if (history.length === 0) {
      // Unknown model with no history — conservative defaults
      return {
        model,
        successRate: 0.50,
        avgCostPerFix: 0.05,
        avgTokensPerFix: 3000,
        avgDurationMs: 15000,
        totalAttempts: 0,
        totalSuccesses: 0,
        complexityScores: { low: 0.60, medium: 0.40, high: 0.20 },
        taskTypeScores: {}
      }
    }

    const successes = history.filter(e => e.success)
    const realSuccessRate = successes.length / history.length
    const realAvgCost = history.length > 0
      ? history.reduce((sum, e) => sum + e.cost, 0) / history.length
      : 0
    const realAvgTokens = history.length > 0
      ? history.reduce((sum, e) => sum + e.tokensUsed, 0) / history.length
      : 0
    const realAvgDuration = history.length > 0
      ? history.reduce((sum, e) => sum + e.durationMs, 0) / history.length
      : 0

    // Blend with defaults: weight = min(history.length, 20) / 20
    // At 20+ real entries, we rely entirely on real data
    const BLEND_THRESHOLD = 20
    const realWeight = Math.min(history.length, BLEND_THRESHOLD) / BLEND_THRESHOLD
    const priorWeight = 1 - realWeight

    const prior = defaults ?? {
      successRate: 0.50,
      avgCostPerFix: 0.05,
      avgTokensPerFix: 3000,
      avgDurationMs: 15000,
      complexityScores: { low: 0.60, medium: 0.40, high: 0.20 }
    }

    const blendedSuccessRate = realWeight * realSuccessRate + priorWeight * prior.successRate
    const blendedCost = realWeight * realAvgCost + priorWeight * prior.avgCostPerFix
    const blendedTokens = realWeight * realAvgTokens + priorWeight * prior.avgTokensPerFix
    const blendedDuration = realWeight * realAvgDuration + priorWeight * prior.avgDurationMs

    // Complexity breakdown from real data
    const complexityScores = { low: 0, medium: 0, high: 0 }
    for (const c of ['low', 'medium', 'high'] as const) {
      const cEntries = history.filter(e => e.complexity === c)
      if (cEntries.length > 0) {
        const cReal = cEntries.filter(e => e.success).length / cEntries.length
        const cWeight = Math.min(cEntries.length, 10) / 10
        complexityScores[c] = cWeight * cReal + (1 - cWeight) * prior.complexityScores[c]
      } else {
        complexityScores[c] = prior.complexityScores[c]
      }
    }

    // Task type scores from real data (severity-based grouping)
    const taskTypeScores: Record<string, number> = {}
    const severities = new Set(history.map(e => e.severity))
    for (const sev of severities) {
      const sevEntries = history.filter(e => e.severity === sev)
      if (sevEntries.length >= 2) {
        taskTypeScores[sev] = sevEntries.filter(e => e.success).length / sevEntries.length
      }
    }

    return {
      model,
      successRate: blendedSuccessRate,
      avgCostPerFix: blendedCost,
      avgTokensPerFix: blendedTokens,
      avgDurationMs: blendedDuration,
      totalAttempts: history.length,
      totalSuccesses: successes.length,
      complexityScores,
      taskTypeScores
    }
  }

  /**
   * Get stats for all known models (those with defaults + any with history).
   */
  getAllStats(): AgentStats[] {
    const history = statsStore.get('history')
    const modelsWithHistory = new Set(history.map(e => e.model))
    const allModels = new Set([...Object.keys(DEFAULT_STATS), ...modelsWithHistory])
    return Array.from(allModels).map(m => this.getStats(m))
  }

  /**
   * Get raw history for a model.
   */
  getHistory(model: string, limit = 50): ModelHistoryEntry[] {
    return statsStore.get('history')
      .filter(e => e.model === model)
      .slice(-limit)
  }

  /**
   * Rank models by cost-effectiveness (success per dollar).
   * Free models with decent success rate rank highest.
   */
  getLeaderboard(): { model: string; costEffectiveness: number; totalFixes: number; successRate: number; avgCost: number }[] {
    return this.getAllStats()
      .map(s => ({
        model: s.model,
        // For free models (cost=0), use a large number scaled by success rate
        costEffectiveness: s.avgCostPerFix === 0
          ? s.successRate * 1000
          : s.successRate / s.avgCostPerFix,
        totalFixes: s.totalSuccesses,
        successRate: s.successRate,
        avgCost: s.avgCostPerFix
      }))
      .sort((a, b) => b.costEffectiveness - a.costEffectiveness)
  }

  /**
   * Clear all recorded history.
   */
  reset(): void {
    statsStore.set('history', [])
  }
}

export const agentStatsTracker = new AgentStatsTracker()
