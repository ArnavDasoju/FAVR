/**
 * Smart Context Windowing — sends only the files relevant to a subtask,
 * not the entire codebase. Builds a dependency graph from imports.
 *
 * Strategy:
 * 1. Identify the target file(s) from the subtask prompt
 * 2. Trace imports to find direct dependencies
 * 3. Start minimal: target + direct imports
 * 4. Agent can request more files if needed
 * 5. Track tokens saved vs "send everything" approach
 */

import { readFileSync, existsSync } from 'fs'
import { join, dirname, resolve, extname } from 'path'

export interface ContextWindow {
  files: Map<string, string> // path → content
  totalTokens: number
  naiveTokens: number // what it would cost to send everything
  tokensSaved: number
}

// Max tokens for context window
const MAX_CONTEXT_TOKENS = 12000

// Extensions we can parse for imports
const PARSEABLE_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'])

/**
 * Build a minimal context window for a subtask.
 */
export function buildContextWindow(opts: {
  projectDir: string
  subtaskPrompt: string
  allFiles: string[] // all source files in the project
}): ContextWindow {
  const { projectDir, subtaskPrompt, allFiles } = opts

  // Step 1: Identify target files from the prompt
  const targetFiles = identifyTargetFiles(subtaskPrompt, allFiles)

  // Step 2: Trace imports from target files
  const relevantFiles = new Set<string>()
  for (const file of targetFiles) {
    relevantFiles.add(file)
    const imports = traceImports(join(projectDir, file), projectDir)
    for (const imp of imports) {
      relevantFiles.add(imp)
    }
  }

  // Step 3: Build the context with token budget
  const files = new Map<string, string>()
  let totalTokens = 0

  // Priority: target files first, then imports
  const ordered = [
    ...targetFiles,
    ...[...relevantFiles].filter((f) => !targetFiles.includes(f))
  ]

  for (const file of ordered) {
    const fullPath = join(projectDir, file)
    if (!existsSync(fullPath)) continue

    try {
      const content = readFileSync(fullPath, 'utf-8')
      const tokens = estimateTokens(content)

      if (totalTokens + tokens > MAX_CONTEXT_TOKENS) {
        // Truncate large files
        const remaining = MAX_CONTEXT_TOKENS - totalTokens
        if (remaining > 200) {
          const truncated = content.slice(0, remaining * 4) + '\n// ... truncated'
          files.set(file, truncated)
          totalTokens += remaining
        }
        break
      }

      files.set(file, content)
      totalTokens += tokens
    } catch {
      // Skip unreadable files
    }
  }

  // Estimate naive cost (sending all files)
  let naiveTokens = 0
  for (const file of allFiles) {
    try {
      const content = readFileSync(join(projectDir, file), 'utf-8')
      naiveTokens += estimateTokens(content)
    } catch {
      // Skip
    }
  }

  return {
    files,
    totalTokens,
    naiveTokens,
    tokensSaved: naiveTokens - totalTokens
  }
}

/**
 * Identify files mentioned or relevant to a prompt.
 */
function identifyTargetFiles(prompt: string, allFiles: string[]): string[] {
  const targets: string[] = []
  const promptLower = prompt.toLowerCase()

  // Direct file references
  for (const file of allFiles) {
    const basename = file.split('/').pop()?.toLowerCase() ?? ''
    const nameNoExt = basename.replace(/\.[^.]+$/, '')

    if (promptLower.includes(basename) || promptLower.includes(nameNoExt)) {
      targets.push(file)
    }
  }

  // Keyword-based file matching
  const keywordMap: Record<string, string[]> = {
    'auth': ['auth', 'login', 'session', 'middleware'],
    'style': ['css', 'styles', 'theme', 'tailwind'],
    'test': ['test', 'spec', '__tests__'],
    'api': ['api', 'route', 'handler', 'endpoint'],
    'database': ['schema', 'migration', 'prisma', 'drizzle', 'model'],
    'config': ['config', 'env', 'settings'],
    'component': ['component', 'page', 'layout'],
  }

  for (const [keyword, filePatterns] of Object.entries(keywordMap)) {
    if (promptLower.includes(keyword)) {
      for (const file of allFiles) {
        const fileLower = file.toLowerCase()
        if (filePatterns.some((p) => fileLower.includes(p)) && !targets.includes(file)) {
          targets.push(file)
        }
      }
    }
  }

  // Limit to top 5 most relevant
  return targets.slice(0, 5)
}

/**
 * Trace import statements from a file to find dependencies.
 * Returns relative paths from projectDir.
 */
function traceImports(filePath: string, projectDir: string, depth = 0): string[] {
  if (depth > 2) return [] // Max 2 levels deep
  if (!existsSync(filePath)) return []

  const ext = extname(filePath)
  if (!PARSEABLE_EXTENSIONS.has(ext)) return []

  try {
    const content = readFileSync(filePath, 'utf-8')
    const imports: string[] = []

    // Match import/require statements
    const importRegex = /(?:import|require)\s*\(?['"]([^'"]+)['"]\)?/g
    let match: RegExpExecArray | null
    while ((match = importRegex.exec(content)) !== null) {
      const specifier = match[1]

      // Skip node_modules / bare imports
      if (!specifier.startsWith('.') && !specifier.startsWith('/')) continue

      const resolved = resolveImport(specifier, dirname(filePath))
      if (resolved && existsSync(resolved)) {
        const relPath = resolved.replace(projectDir + '/', '')
        imports.push(relPath)

        // Recurse one more level
        if (depth < 2) {
          const deeper = traceImports(resolved, projectDir, depth + 1)
          imports.push(...deeper)
        }
      }
    }

    return [...new Set(imports)]
  } catch {
    return []
  }
}

/**
 * Resolve a relative import to an absolute file path.
 */
function resolveImport(specifier: string, fromDir: string): string | null {
  const base = resolve(fromDir, specifier)

  // Try exact path
  if (existsSync(base) && !require('fs').statSync(base).isDirectory()) return base

  // Try common extensions
  for (const ext of ['.ts', '.tsx', '.js', '.jsx']) {
    if (existsSync(base + ext)) return base + ext
  }

  // Try index files
  for (const ext of ['.ts', '.tsx', '.js', '.jsx']) {
    const indexPath = join(base, `index${ext}`)
    if (existsSync(indexPath)) return indexPath
  }

  return null
}

/**
 * Format context window as a string for the prompt.
 */
export function formatContextForPrompt(context: ContextWindow): string {
  const parts: string[] = []

  parts.push('## Relevant Files')
  parts.push('')

  for (const [path, content] of context.files) {
    const ext = extname(path).slice(1) || 'text'
    parts.push(`### ${path}`)
    parts.push(`\`\`\`${ext}`)
    parts.push(content)
    parts.push('```')
    parts.push('')
  }

  return parts.join('\n')
}

function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4)
}
