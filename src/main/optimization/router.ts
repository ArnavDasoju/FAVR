/**
 * Free-First Router — picks the cheapest capable model for each subtask.
 *
 * Priority:
 * 1. Ollama (free, local)
 * 2. Gemini Flash (free tier)
 * 3. DeepSeek (cheap)
 * 4. Claude / GPT (expensive, most capable)
 */

export interface ModelCapability {
  model: string
  costPer1kTokens: number
  maxComplexity: 'low' | 'medium' | 'high'
  taskTypes: string[] // what it's good at, empty = general purpose
  available: boolean
}

const DEFAULT_MODELS: ModelCapability[] = [
  {
    model: 'ollama/llama3',
    costPer1kTokens: 0,
    maxComplexity: 'medium',
    taskTypes: ['docs', 'refactor', 'css'],
    available: false // checked at runtime
  },
  {
    model: 'google/gemini-2.5-flash',
    costPer1kTokens: 0,
    maxComplexity: 'medium',
    taskTypes: ['docs', 'css', 'test'],
    available: true
  },
  {
    model: 'deepseek/deepseek-chat',
    costPer1kTokens: 0.001,
    maxComplexity: 'high',
    taskTypes: [], // general purpose
    available: true
  },
  {
    model: 'anthropic/claude-sonnet-4.6',
    costPer1kTokens: 0.003,
    maxComplexity: 'high',
    taskTypes: [], // general purpose
    available: true
  },
  {
    model: 'openai/gpt-5.4',
    costPer1kTokens: 0.005,
    maxComplexity: 'high',
    taskTypes: [], // general purpose
    available: true
  }
]

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
   * Pick the cheapest model that can handle this task.
   */
  route(taskType: string, complexity: 'low' | 'medium' | 'high'): string {
    const candidates = this.models
      .filter((m) => m.available)
      .filter((m) => COMPLEXITY_ORDER[m.maxComplexity] >= COMPLEXITY_ORDER[complexity])
      .filter((m) => m.taskTypes.length === 0 || m.taskTypes.includes(taskType))
      .sort((a, b) => a.costPer1kTokens - b.costPer1kTokens)

    return candidates[0]?.model ?? 'anthropic/claude-sonnet-4.6'
  }

  /**
   * Estimate cost for a task given model and complexity.
   */
  estimateCost(model: string, complexity: 'low' | 'medium' | 'high'): number {
    const capability = this.models.find((m) => m.model === model)
    if (!capability) return 0

    const tokenEstimates = { low: 2000, medium: 8000, high: 20000 }
    const tokens = tokenEstimates[complexity]

    return (tokens / 1000) * capability.costPer1kTokens
  }

  /**
   * Get cost savings by comparing routed model vs default expensive model.
   */
  getSavings(taskType: string, complexity: 'low' | 'medium' | 'high'): { routed: string; routedCost: number; defaultCost: number; saved: number } {
    const routed = this.route(taskType, complexity)
    const routedCost = this.estimateCost(routed, complexity)
    const defaultCost = this.estimateCost('anthropic/claude-sonnet-4.6', complexity)

    return {
      routed,
      routedCost,
      defaultCost,
      saved: defaultCost - routedCost
    }
  }
}

export const modelRouter = new ModelRouter()
