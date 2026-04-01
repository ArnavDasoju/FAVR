/**
 * Task Chunker — breaks a user prompt into subtasks.
 *
 * Tier 1: Free heuristic (pattern matching)
 * Tier 2: LLM decomposition (costs tokens, better quality)
 */

export interface ChunkedSubtask {
  prompt: string
  suggestedModel: string | null
  taskType: string // css, logic, test, refactor, docs, etc.
  complexity: 'low' | 'medium' | 'high'
}

// Pattern → task type mapping for heuristic chunking
const HEURISTIC_PATTERNS: { pattern: RegExp; taskType: string; suggestedModel: string | null }[] = [
  // CSS / styling
  { pattern: /\b(css|style|color|theme|dark mode|light mode|font|layout|responsive|tailwind|margin|padding|border|animation)\b/i, taskType: 'css', suggestedModel: null },
  // Testing
  { pattern: /\b(test|spec|jest|vitest|cypress|playwright|assert|expect|coverage)\b/i, taskType: 'test', suggestedModel: null },
  // Documentation
  { pattern: /\b(readme|docs|documentation|comment|jsdoc|typedoc)\b/i, taskType: 'docs', suggestedModel: null },
  // Database / schema
  { pattern: /\b(database|schema|migration|sql|postgres|prisma|drizzle|supabase|query|table|column)\b/i, taskType: 'database', suggestedModel: null },
  // API / backend
  { pattern: /\b(api|endpoint|route|handler|middleware|auth|jwt|session|cookie)\b/i, taskType: 'api', suggestedModel: null },
  // DevOps / config
  { pattern: /\b(deploy|ci|cd|docker|env|config|build|package|dependency)\b/i, taskType: 'devops', suggestedModel: null },
  // Refactoring
  { pattern: /\b(refactor|clean|organize|extract|rename|restructure|simplify)\b/i, taskType: 'refactor', suggestedModel: null },
  // Performance
  { pattern: /\b(performance|optimize|cache|lazy|bundle|speed|slow|profile)\b/i, taskType: 'performance', suggestedModel: null },
]

/**
 * Tier 1: Free heuristic chunking.
 * For simple tasks, returns as a single subtask with detected type.
 * For compound tasks (multiple patterns match), splits into subtasks.
 */
export function heuristicChunk(prompt: string): ChunkedSubtask[] {
  const matchedTypes = new Set<string>()
  const matchedPatterns: typeof HEURISTIC_PATTERNS = []

  for (const entry of HEURISTIC_PATTERNS) {
    if (entry.pattern.test(prompt)) {
      if (!matchedTypes.has(entry.taskType)) {
        matchedTypes.add(entry.taskType)
        matchedPatterns.push(entry)
      }
    }
  }

  // Single type or no match — return as one task
  if (matchedPatterns.length <= 1) {
    const taskType = matchedPatterns[0]?.taskType ?? 'general'
    return [
      {
        prompt,
        suggestedModel: matchedPatterns[0]?.suggestedModel ?? null,
        taskType,
        complexity: estimateComplexity(prompt)
      }
    ]
  }

  // Multiple types detected — split into subtasks
  return matchedPatterns.map((entry) => ({
    prompt: `${prompt} (focus on: ${entry.taskType})`,
    suggestedModel: entry.suggestedModel,
    taskType: entry.taskType,
    complexity: estimateComplexity(prompt)
  }))
}

/**
 * Tier 2: LLM-based chunking (costs tokens).
 * Sends prompt to classifier to decompose into subtasks.
 */
export async function llmChunk(
  prompt: string,
  classifyFn: (input: string) => Promise<{ subtasks: ChunkedSubtask[] }>
): Promise<ChunkedSubtask[]> {
  const result = await classifyFn(prompt)
  return result.subtasks
}

/**
 * Main entry point: try heuristic first, fall back to LLM if the task looks complex.
 */
export async function chunkTask(
  prompt: string,
  options: {
    forceHeuristic?: boolean
    classifyFn?: (input: string) => Promise<{ subtasks: ChunkedSubtask[] }>
  } = {}
): Promise<ChunkedSubtask[]> {
  const heuristicResult = heuristicChunk(prompt)

  // If heuristic produced a good split or user forced heuristic, use it
  if (options.forceHeuristic || !options.classifyFn) {
    return heuristicResult
  }

  // If the task is complex and we have an LLM, use it
  const complexity = estimateComplexity(prompt)
  if (complexity === 'high') {
    try {
      return await llmChunk(prompt, options.classifyFn)
    } catch {
      // Fallback to heuristic on LLM failure
      return heuristicResult
    }
  }

  return heuristicResult
}

function estimateComplexity(prompt: string): 'low' | 'medium' | 'high' {
  const wordCount = prompt.split(/\s+/).length
  const hasMultipleSentences = (prompt.match(/[.!?]/g)?.length ?? 0) > 1
  const hasConjunctions = /\b(and|then|after|also|plus)\b/i.test(prompt)

  if (wordCount > 30 || (hasMultipleSentences && hasConjunctions)) return 'high'
  if (wordCount > 12 || hasMultipleSentences || hasConjunctions) return 'medium'
  return 'low'
}
