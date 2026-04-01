/**
 * Prompt Cache Manager — builds a reusable "project snapshot" that gets
 * pinned as a cached system message across all subtask calls.
 *
 * How it works:
 * 1. On flow start, scan the project for key files (package.json, tsconfig, etc.)
 * 2. Build a compact project context string
 * 3. Mark it with cache_control for Anthropic / system_fingerprint for OpenAI
 * 4. All subtask prompts reuse the same cached prefix → ~90% token savings on context
 *
 * The cache is invalidated when files change (tracked via mtime).
 */

import { readFileSync, statSync, readdirSync } from 'fs'
import { join, relative, extname } from 'path'

export interface ProjectSnapshot {
  projectDir: string
  fileTree: string
  keyFiles: Record<string, string> // path → content (truncated)
  builtAt: number
  tokenEstimate: number
}

interface CacheEntry {
  snapshot: ProjectSnapshot
  systemMessage: string
  fingerprint: string // hash for invalidation
}

// Files that provide important project context
const KEY_FILE_PATTERNS = [
  'package.json',
  'tsconfig.json',
  'tsconfig.*.json',
  '.env.example',
  'next.config.*',
  'vite.config.*',
  'tailwind.config.*',
  'prisma/schema.prisma',
  'drizzle.config.*',
  'README.md'
]

// Directories to skip when building file tree
const SKIP_DIRS = new Set([
  'node_modules', '.git', '.next', 'dist', 'out', 'build',
  '.cache', 'coverage', '.turbo', '.vercel'
])

// Max content per key file (chars)
const MAX_FILE_CONTENT = 2000

// Max depth for file tree
const MAX_TREE_DEPTH = 4

class PromptCacheManager {
  private cache: Map<string, CacheEntry> = new Map()
  private stats = { hits: 0, misses: 0, tokensSaved: 0 }

  /**
   * Get or build a cached project snapshot.
   * Returns the system message to prepend to all subtask prompts.
   */
  getProjectContext(projectDir: string): { systemMessage: string; fromCache: boolean; tokenEstimate: number } {
    const fingerprint = this.computeFingerprint(projectDir)
    const cached = this.cache.get(projectDir)

    if (cached && cached.fingerprint === fingerprint) {
      this.stats.hits++
      this.stats.tokensSaved += cached.snapshot.tokenEstimate
      return {
        systemMessage: cached.systemMessage,
        fromCache: true,
        tokenEstimate: cached.snapshot.tokenEstimate
      }
    }

    // Build fresh snapshot
    this.stats.misses++
    const snapshot = this.buildSnapshot(projectDir)
    const systemMessage = this.formatSystemMessage(snapshot)

    this.cache.set(projectDir, { snapshot, systemMessage, fingerprint })

    return {
      systemMessage,
      fromCache: false,
      tokenEstimate: snapshot.tokenEstimate
    }
  }

  /**
   * Build a project snapshot by scanning the directory.
   */
  private buildSnapshot(projectDir: string): ProjectSnapshot {
    const fileTree = this.buildFileTree(projectDir, 0)
    const keyFiles = this.collectKeyFiles(projectDir)

    // Rough token estimate: ~4 chars per token
    const totalChars = fileTree.length + Object.values(keyFiles).reduce((sum, c) => sum + c.length, 0)
    const tokenEstimate = Math.ceil(totalChars / 4)

    return {
      projectDir,
      fileTree,
      keyFiles,
      builtAt: Date.now(),
      tokenEstimate
    }
  }

  /**
   * Build a compact file tree string.
   */
  private buildFileTree(dir: string, depth: number, prefix = ''): string {
    if (depth > MAX_TREE_DEPTH) return ''

    try {
      const entries = readdirSync(dir, { withFileTypes: true })
        .filter((e) => !e.name.startsWith('.') || e.name === '.env.example')
        .filter((e) => !SKIP_DIRS.has(e.name))
        .sort((a, b) => {
          // Directories first
          if (a.isDirectory() && !b.isDirectory()) return -1
          if (!a.isDirectory() && b.isDirectory()) return 1
          return a.name.localeCompare(b.name)
        })

      const lines: string[] = []
      for (const entry of entries) {
        const path = join(dir, entry.name)
        if (entry.isDirectory()) {
          lines.push(`${prefix}${entry.name}/`)
          lines.push(this.buildFileTree(path, depth + 1, prefix + '  '))
        } else {
          lines.push(`${prefix}${entry.name}`)
        }
      }

      return lines.filter(Boolean).join('\n')
    } catch {
      return ''
    }
  }

  /**
   * Collect contents of key project files.
   */
  private collectKeyFiles(projectDir: string): Record<string, string> {
    const result: Record<string, string> = {}

    for (const pattern of KEY_FILE_PATTERNS) {
      // Simple glob: handle * as wildcard
      if (pattern.includes('*')) {
        const dir = pattern.includes('/') ? join(projectDir, pattern.split('/')[0]) : projectDir
        const ext = pattern.split('.').pop()
        try {
          const files = readdirSync(dir).filter((f) => {
            if (ext && ext !== '*') return f.endsWith(`.${ext}`)
            return f.startsWith(pattern.split('*')[0])
          })
          for (const file of files) {
            const fullPath = join(dir, file)
            const relPath = relative(projectDir, fullPath)
            result[relPath] = this.readTruncated(fullPath)
          }
        } catch {
          // Directory doesn't exist
        }
      } else {
        const fullPath = join(projectDir, pattern)
        try {
          result[pattern] = this.readTruncated(fullPath)
        } catch {
          // File doesn't exist
        }
      }
    }

    return result
  }

  private readTruncated(path: string): string {
    const content = readFileSync(path, 'utf-8')
    if (content.length > MAX_FILE_CONTENT) {
      return content.slice(0, MAX_FILE_CONTENT) + '\n... (truncated)'
    }
    return content
  }

  /**
   * Format the snapshot as a system message.
   */
  private formatSystemMessage(snapshot: ProjectSnapshot): string {
    const parts: string[] = []

    parts.push(`Project: ${snapshot.projectDir}`)
    parts.push('')
    parts.push('## File Structure')
    parts.push('```')
    parts.push(snapshot.fileTree)
    parts.push('```')

    for (const [path, content] of Object.entries(snapshot.keyFiles)) {
      const ext = extname(path).slice(1) || 'text'
      parts.push('')
      parts.push(`## ${path}`)
      parts.push(`\`\`\`${ext}`)
      parts.push(content)
      parts.push('```')
    }

    return parts.join('\n')
  }

  /**
   * Simple fingerprint based on key file mtimes.
   */
  private computeFingerprint(projectDir: string): string {
    const mtimes: string[] = []
    for (const pattern of KEY_FILE_PATTERNS) {
      if (pattern.includes('*')) continue
      try {
        const stat = statSync(join(projectDir, pattern))
        mtimes.push(`${pattern}:${stat.mtimeMs}`)
      } catch {
        mtimes.push(`${pattern}:missing`)
      }
    }
    return mtimes.join('|')
  }

  /**
   * Wrap messages with cache control hints for providers.
   */
  buildCachedMessages(
    projectDir: string,
    subtaskPrompt: string
  ): Array<{ role: string; content: string; cache_control?: { type: string } }> {
    const { systemMessage } = this.getProjectContext(projectDir)

    return [
      {
        role: 'system',
        content: systemMessage,
        cache_control: { type: 'ephemeral' } // Anthropic cache hint
      },
      {
        role: 'user',
        content: subtaskPrompt
      }
    ]
  }

  /**
   * Invalidate cache for a project (e.g., after agent makes changes).
   */
  invalidate(projectDir: string) {
    this.cache.delete(projectDir)
  }

  getStats() {
    return { ...this.stats }
  }
}

export const promptCache = new PromptCacheManager()
