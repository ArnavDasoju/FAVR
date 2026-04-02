/**
 * File Applier — parses LLM output for code blocks and writes them to disk.
 *
 * Handles multiple output styles from different models:
 *
 * Style 1 (strict — FILE: marker):
 *   FILE: src/index.js
 *   ```
 *   code here
 *   ```
 *
 * Style 2 (fence with path):
 *   ```typescript:src/index.ts
 *   code here
 *   ```
 *
 * Style 3 (conversational — what small models like Llama3 actually do):
 *   "Add the following code to `index.js`:"
 *   ```javascript
 *   console.log("hello")
 *   ```
 */

import { writeFileSync, mkdirSync, unlinkSync, existsSync } from 'fs'
import { join, dirname } from 'path'

export interface FileChange {
  filePath: string
  content: string
  action: 'create' | 'update' | 'delete'
}

// File extensions we recognize as real code files
const CODE_EXTENSIONS = /\.(js|ts|jsx|tsx|py|css|html|json|md|yaml|yml|toml|rs|go|rb|sh|sql|vue|svelte|mjs|cjs|env|txt|xml|cfg|ini|conf)$/

// Languages that map to file extensions (for guessing from ```lang blocks)
const LANG_TO_EXT: Record<string, string> = {
  javascript: '.js',
  typescript: '.ts',
  python: '.py',
  json: '.json',
  html: '.html',
  css: '.css',
  bash: '.sh',
  shell: '.sh',
  sh: '.sh',
  sql: '.sql',
  rust: '.rs',
  go: '.go',
  ruby: '.rb',
  yaml: '.yaml',
  yml: '.yaml',
  toml: '.toml',
  jsx: '.jsx',
  tsx: '.tsx',
  xml: '.xml',
  vue: '.vue',
  svelte: '.svelte',
  js: '.js',
  ts: '.ts',
  py: '.py',
}

// Content patterns that indicate shell commands, NOT file content
const SHELL_PATTERNS = [
  /^\s*(mkdir|cd|touch|npm|node|yarn|pnpm|brew|pip|cargo|go\s+run|python|ruby)\s/,
  /^\s*\$\s/,
  /^\s*(sudo|chmod|chown|rm|mv|cp|ls|cat|echo)\s/,
]

// Content patterns that indicate plain output, NOT file content
const OUTPUT_PATTERNS = [
  /^Hello,?\s*World!?\s*$/,
  /^\s*\d+\s*$/,
  /^(true|false|null|undefined)\s*$/,
]

/**
 * Parse LLM output and extract file changes.
 */
export function parseFileChanges(output: string): FileChange[] {
  const changes: FileChange[] = []
  const lines = output.split('\n')

  let i = 0
  while (i < lines.length) {
    const line = lines[i]

    // Check for DELETE: marker
    const deleteMatch = line.match(/^DELETE:\s*(.+)$/)
    if (deleteMatch) {
      changes.push({
        filePath: deleteMatch[1].trim(),
        content: '',
        action: 'delete'
      })
      i++
      continue
    }

    // Style 1: FILE: marker (or common variations)
    const fileMatch = line.match(/^\*{0,2}FILE:\*{0,2}\s*`?(.+?)`?\s*$/) ?? line.match(/^file:\s*`?(.+?)`?\s*$/i)
    if (fileMatch) {
      const filePath = fileMatch[1].trim()
      let j = i + 1
      while (j < lines.length && lines[j].trim() === '') j++

      if (j < lines.length && lines[j].match(/^```/)) {
        const block = extractCodeBlock(lines, j)
        if (block) {
          changes.push({ filePath, content: block.content, action: 'create' })
          i = block.endLine + 1
          continue
        }
      }
      i++
      continue
    }

    // Style 2: Fenced code block with path in info string
    const fencePathMatch = line.match(/^```[\w]*:(.+)$/)
    if (fencePathMatch) {
      const filePath = fencePathMatch[1].trim()
      const block = extractCodeBlock(lines, i)
      if (block) {
        changes.push({ filePath, content: block.content, action: 'create' })
        i = block.endLine + 1
        continue
      }
    }

    // Style 2b: Info string is a file path
    const pathFenceMatch = line.match(/^```(\S+\/\S+\.\w+)$/)
    if (pathFenceMatch) {
      const filePath = pathFenceMatch[1].trim()
      const block = extractCodeBlock(lines, i)
      if (block) {
        changes.push({ filePath, content: block.content, action: 'create' })
        i = block.endLine + 1
        continue
      }
    }

    // Style 3: Conversational — code block with a language tag,
    // preceded by text mentioning a filename like "`index.js`" or "index.js"
    const fenceWithLang = line.match(/^```(\w+)\s*$/)
    if (fenceWithLang) {
      const lang = fenceWithLang[1].toLowerCase()
      const block = extractCodeBlock(lines, i)

      if (block && block.content.trim().length > 0 && !isShellCommand(block.content) && !isPlainOutput(block.content)) {
        // Look back up to 5 lines for a filename mention
        const lookback = lines.slice(Math.max(0, i - 5), i).join(' ')
        const filename = extractFilenameFromText(lookback)

        if (filename) {
          const alreadyHave = changes.some((c) => c.filePath === filename)
          if (!alreadyHave) {
            changes.push({ filePath: filename, content: block.content, action: 'create' })
            i = block.endLine + 1
            continue
          }
        } else if (lang in LANG_TO_EXT && changes.length === 0) {
          // If no filename found but we have a language and this is the first code block,
          // try to infer a reasonable filename from the task
          // Skip this — we only write files when we know the filename
        }
      }

      if (block) {
        i = block.endLine + 1
        continue
      }
    }

    i++
  }

  return changes
}

/**
 * Extract a filename from conversational text.
 * Matches patterns like:
 *   - `index.js`
 *   - "add code to index.js"
 *   - "create index.js"
 *   - "**index.js**"
 */
function extractFilenameFromText(text: string): string | null {
  // Try backtick-wrapped filenames first (most reliable)
  const backtickMatch = text.match(/`([a-zA-Z0-9_\-./]+\.\w{1,5})`/)
  if (backtickMatch && CODE_EXTENSIONS.test(backtickMatch[1])) {
    return backtickMatch[1]
  }

  // Try bold-wrapped filenames
  const boldMatch = text.match(/\*\*([a-zA-Z0-9_\-./]+\.\w{1,5})\*\*/)
  if (boldMatch && CODE_EXTENSIONS.test(boldMatch[1])) {
    return boldMatch[1]
  }

  // Try "to/in/for [filename]" patterns
  const contextMatch = text.match(/(?:to|in|for|create|add|update|modify|edit)\s+(?:the\s+)?(?:file\s+)?`?([a-zA-Z0-9_\-./]+\.\w{1,5})`?/i)
  if (contextMatch && CODE_EXTENSIONS.test(contextMatch[1])) {
    return contextMatch[1]
  }

  // Try "filename:" at end of line
  const colonMatch = text.match(/([a-zA-Z0-9_\-./]+\.\w{1,5})\s*:\s*$/)
  if (colonMatch && CODE_EXTENSIONS.test(colonMatch[1])) {
    return colonMatch[1]
  }

  return null
}

/**
 * Check if content looks like shell commands rather than file content.
 */
function isShellCommand(content: string): boolean {
  const firstLine = content.trim().split('\n')[0]
  return SHELL_PATTERNS.some((p) => p.test(firstLine))
}

/**
 * Check if content looks like plain output rather than code.
 */
function isPlainOutput(content: string): boolean {
  const trimmed = content.trim()
  // Single short line that looks like output
  if (trimmed.split('\n').length <= 2 && trimmed.length < 50) {
    return OUTPUT_PATTERNS.some((p) => p.test(trimmed))
  }
  return false
}

/**
 * Extract content from a fenced code block starting at the given line.
 */
function extractCodeBlock(lines: string[], startLine: number): { content: string; endLine: number } | null {
  if (!lines[startLine].startsWith('```')) return null

  const contentLines: string[] = []
  let j = startLine + 1

  while (j < lines.length) {
    if (lines[j].match(/^```\s*$/)) {
      return {
        content: contentLines.join('\n'),
        endLine: j
      }
    }
    contentLines.push(lines[j])
    j++
  }

  return {
    content: contentLines.join('\n'),
    endLine: j - 1
  }
}

/**
 * Apply parsed file changes to the project directory.
 */
export function applyFileChanges(projectDir: string, changes: FileChange[]): string[] {
  const applied: string[] = []

  for (const change of changes) {
    const resolved = join(projectDir, change.filePath)
    if (!resolved.startsWith(projectDir)) {
      console.warn(`[file-applier] Skipping path traversal attempt: ${change.filePath}`)
      continue
    }

    try {
      if (change.action === 'delete') {
        if (existsSync(resolved)) {
          unlinkSync(resolved)
          applied.push(change.filePath)
          console.log(`[file-applier] Deleted: ${change.filePath}`)
        }
      } else {
        mkdirSync(dirname(resolved), { recursive: true })
        writeFileSync(resolved, change.content, 'utf-8')
        applied.push(change.filePath)
        console.log(`[file-applier] Wrote: ${change.filePath}`)
      }
    } catch (err) {
      console.error(`[file-applier] Failed to apply ${change.filePath}:`, err)
    }
  }

  return applied
}

/**
 * Parse LLM output and apply file changes in one step.
 * If strict parsing finds nothing, falls back to task-aware extraction.
 */
export function applyLlmOutput(projectDir: string, output: string, taskPrompt?: string): string[] {
  let changes = parseFileChanges(output)

  // Fallback 1: task-aware extraction (looks for code blocks + matches to task filenames)
  if (changes.length === 0 && taskPrompt) {
    console.log('[file-applier] Strict parsing found nothing, trying task-aware extraction')
    changes = extractFromTask(output, taskPrompt)
  }

  // Fallback 2: raw code extraction (for models that don't use code fences at all)
  if (changes.length === 0 && taskPrompt) {
    console.log('[file-applier] Task-aware extraction found nothing, trying raw code extraction')
    changes = extractRawCode(output, taskPrompt)
  }

  if (changes.length === 0) {
    console.log('[file-applier] No file changes found in LLM output')
    return []
  }

  console.log(`[file-applier] Found ${changes.length} file change(s):`, changes.map((c) => c.filePath))
  return applyFileChanges(projectDir, changes)
}

/**
 * Task-aware extraction — uses the task prompt to figure out what files to create.
 * Extracts filenames from the task, then finds matching code blocks in the output.
 */
function extractFromTask(output: string, taskPrompt: string): FileChange[] {
  const changes: FileChange[] = []

  // Extract filenames mentioned in the task prompt
  const taskFilenames: string[] = []

  // Match explicit filenames like "index.js", "src/app.ts", etc.
  const filenameRegex = /\b([a-zA-Z0-9_\-./]*[a-zA-Z0-9_\-]+\.\w{1,5})\b/g
  let match
  while ((match = filenameRegex.exec(taskPrompt)) !== null) {
    if (CODE_EXTENSIONS.test(match[1])) {
      taskFilenames.push(match[1])
    }
  }

  if (taskFilenames.length === 0) {
    // No filenames in task — try to infer from keywords
    // "create a hello world express server" → index.js
    // "add a python script" → main.py
    const lower = taskPrompt.toLowerCase()
    if (lower.includes('.js') || lower.includes('javascript') || lower.includes('node') || lower.includes('express')) {
      taskFilenames.push('index.js')
    } else if (lower.includes('.ts') || lower.includes('typescript')) {
      taskFilenames.push('index.ts')
    } else if (lower.includes('.py') || lower.includes('python')) {
      taskFilenames.push('main.py')
    } else if (lower.includes('.html') || lower.includes('webpage') || lower.includes('website')) {
      taskFilenames.push('index.html')
    } else if (lower.includes('.css') || lower.includes('stylesheet')) {
      taskFilenames.push('styles.css')
    }
  }

  if (taskFilenames.length === 0) return changes

  // Find all code blocks in the output
  const codeBlocks = extractAllCodeBlocks(output)

  // Filter out shell commands and plain output
  const realCodeBlocks = codeBlocks.filter(
    (b) => b.content.trim().length > 0 && !isShellCommand(b.content) && !isPlainOutput(b.content)
  )

  if (realCodeBlocks.length === 0) return changes

  // Match code blocks to filenames
  // If there's one target file and one real code block, it's a match
  if (taskFilenames.length === 1 && realCodeBlocks.length >= 1) {
    // Use the largest code block (most likely the actual implementation)
    const best = realCodeBlocks.sort((a, b) => b.content.length - a.content.length)[0]
    changes.push({
      filePath: taskFilenames[0],
      content: best.content,
      action: 'create'
    })
  } else {
    // Multiple files — try to match by language/extension
    for (const filename of taskFilenames) {
      const ext = filename.split('.').pop() ?? ''
      const matchingLangs = Object.entries(LANG_TO_EXT)
        .filter(([, e]) => e === `.${ext}`)
        .map(([lang]) => lang)

      const matched = realCodeBlocks.find(
        (b) => matchingLangs.includes(b.lang) || b.lang === ext
      )

      if (matched) {
        changes.push({
          filePath: filename,
          content: matched.content,
          action: 'create'
        })
      }
    }
  }

  return changes
}

/**
 * Extract all fenced code blocks from output.
 */
/**
 * Last resort: extract raw code lines when the model doesn't use code fences.
 * Looks for lines that are actual code (not prose) and collects them.
 */
function extractRawCode(output: string, taskPrompt: string): FileChange[] {
  // Figure out what filename to use
  const filenameRegex = /\b([a-zA-Z0-9_\-./]*[a-zA-Z0-9_\-]+\.\w{1,5})\b/g
  let filename: string | null = null
  let match
  while ((match = filenameRegex.exec(taskPrompt)) !== null) {
    if (CODE_EXTENSIONS.test(match[1])) {
      filename = match[1]
      break
    }
  }

  if (!filename) {
    const lower = taskPrompt.toLowerCase()
    if (lower.includes('javascript') || lower.includes('node') || lower.includes('.js')) filename = 'index.js'
    else if (lower.includes('typescript') || lower.includes('.ts')) filename = 'index.ts'
    else if (lower.includes('python') || lower.includes('.py')) filename = 'main.py'
    else if (lower.includes('html')) filename = 'index.html'
    else filename = 'index.js' // default
  }

  const lines = output.split('\n')

  // Collect lines that look like code, not prose
  const codeLines: string[] = []
  const prosePatterns = [
    /^(Here|This|The|I |You |Let|Sure|Of course|Certainly|To |In |Note|First|Now|Please|That|It |We )/i,
    /^(However|Also|Additionally|Furthermore|Remember|Make sure)/i,
    /^\s*[-*•]\s/,  // bullet points
    /^\s*\d+\.\s/,  // numbered lists
    /^>\s/,         // quote markers
    /^#{1,6}\s/,    // markdown headers
  ]

  // Lines starting with these are agent status lines (not LLM output)
  const agentPrefixes = /^>\s*(Starting|Project|Task|Applied|No file)/

  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue
    if (agentPrefixes.test(trimmed)) continue
    if (trimmed.startsWith('```')) continue

    // Skip lines that look like prose
    const isProse = prosePatterns.some(p => p.test(trimmed))
    if (isProse) continue

    // Skip very short lines that are just words (not code)
    if (trimmed.length < 5 && !/[=();{}[\]<>]/.test(trimmed)) continue

    // Lines with code-like characters are likely code
    const hasCodeChars = /[=();{}[\]<>'"`:\/\\]/.test(trimmed)
    const looksLikeCode = hasCodeChars ||
      /^(const|let|var|function|class|import|export|if|for|while|return|def |print)/.test(trimmed) ||
      /^(console\.|require\(|module\.)/.test(trimmed)

    if (looksLikeCode) {
      codeLines.push(line) // preserve original indentation
    }
  }

  if (codeLines.length === 0) return []

  console.log(`[file-applier] Raw code extraction found ${codeLines.length} code lines`)
  return [{
    filePath: filename,
    content: codeLines.join('\n'),
    action: 'create'
  }]
}

function extractAllCodeBlocks(output: string): Array<{ lang: string; content: string }> {
  const blocks: Array<{ lang: string; content: string }> = []
  const lines = output.split('\n')
  let i = 0

  while (i < lines.length) {
    const fenceMatch = lines[i].match(/^```(\w*)\s*$/)
    if (fenceMatch) {
      const lang = (fenceMatch[1] ?? '').toLowerCase()
      const block = extractCodeBlock(lines, i)
      if (block && block.content.trim()) {
        blocks.push({ lang, content: block.content })
      }
      i = block ? block.endLine + 1 : i + 1
    } else {
      i++
    }
  }

  return blocks
}
