/**
 * Execution Validator — actually runs the code and verifies the output.
 *
 * After an agent writes files, this module:
 * 1. Detects the project type (Node, Python, HTML, etc.)
 * 2. Reads the source code to understand what it does
 * 3. Runs the appropriate command
 * 4. Compares stdout against what the user asked for
 * 5. Returns a confidence score + clear pass/fail reasoning
 */

import { execSync } from 'child_process'
import { existsSync, readFileSync, readdirSync } from 'fs'
import { join, extname } from 'path'

export interface ExecutionResult {
  ran: boolean          // did we manage to run something?
  exitCode: number      // 0 = success
  stdout: string        // captured output
  stderr: string        // captured errors
  command: string       // what we ran
  confidence: number    // 0-100 based on execution result
  reasoning: string     // human-readable explanation
  outputMatch: boolean | null // did the output match the expected?
  expected: string | null     // what we expected to see
  actual: string | null       // what we actually got
}

/**
 * Run and validate generated code against the original task prompt.
 */
export function executeAndValidate(projectDir: string, changedFiles: string[], taskPrompt?: string): ExecutionResult {
  const target = pickExecutionTarget(projectDir, changedFiles)

  if (!target) {
    return {
      ran: false, exitCode: -1, stdout: '', stderr: '', command: '',
      confidence: 60,
      reasoning: 'No executable target found — skipping execution validation',
      outputMatch: null, expected: null, actual: null
    }
  }

  // Step 1: Read the source code to understand what it should do
  const sourceAnalysis = analyzeSource(projectDir, changedFiles, taskPrompt)

  console.log(`[executor] Running: ${target.command} in ${projectDir}`)
  console.log(`[executor] Source analysis: hasOutput=${sourceAnalysis.hasOutputStatements}, expected="${sourceAnalysis.expectedOutput}"`)

  // Step 2: Run the code
  let stdout = ''
  let stderr = ''
  let exitCode = 0

  try {
    stdout = execSync(target.command, {
      cwd: projectDir,
      encoding: 'utf-8',
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, NODE_NO_WARNINGS: '1' }
    }).trim()
  } catch (err: unknown) {
    const execErr = err as { status?: number; stdout?: string; stderr?: string }
    stdout = (execErr.stdout ?? '').toString().trim()
    stderr = (execErr.stderr ?? '').toString().trim()
    exitCode = execErr.status ?? 1
  }

  // Step 3: If code had no output statements and didn't print, extract variable values
  if (!stdout && exitCode === 0 && !sourceAnalysis.hasOutputStatements && changedFiles[0]) {
    stdout = extractVariableValues(projectDir, changedFiles[0])
  }

  const actual = stdout || stderr || null

  // Step 4: If code crashed, analyze the error
  if (exitCode !== 0) {
    const analysis = analyzeError(stderr || stdout, exitCode)
    return {
      ran: true, exitCode, stdout, stderr, command: target.command,
      confidence: analysis.confidence,
      reasoning: analysis.reasoning,
      outputMatch: false,
      expected: sourceAnalysis.expectedOutput,
      actual
    }
  }

  // Step 5: Verify output matches what the user asked for
  const verification = verifyOutput(stdout, taskPrompt, sourceAnalysis)

  console.log(`[executor] Verification: match=${verification.match}, confidence=${verification.confidence}`)

  return {
    ran: true, exitCode: 0, stdout, stderr: '', command: target.command,
    confidence: verification.confidence,
    reasoning: verification.reasoning,
    outputMatch: verification.match,
    expected: sourceAnalysis.expectedOutput,
    actual: stdout || '(no output)'
  }
}

// ── Source Analysis ──────────────────────────────────────────

interface SourceAnalysis {
  hasOutputStatements: boolean  // does the code have console.log/print/etc?
  outputStatements: string[]     // the actual print statements found
  expectedOutput: string | null  // what we think the output should be
}

function analyzeSource(projectDir: string, changedFiles: string[], taskPrompt?: string): SourceAnalysis {
  const result: SourceAnalysis = { hasOutputStatements: false, outputStatements: [], expectedOutput: null }

  for (const file of changedFiles) {
    const fullPath = join(projectDir, file)
    if (!existsSync(fullPath)) continue

    try {
      const code = readFileSync(fullPath, 'utf-8')
      const ext = extname(file).toLowerCase()

      // Find output statements based on language
      const outputPatterns: RegExp[] = []
      if (['.js', '.mjs', '.cjs', '.ts'].includes(ext)) {
        outputPatterns.push(/console\.(log|info|warn|error)\s*\(([^)]*)\)/g)
        outputPatterns.push(/process\.stdout\.write\s*\(([^)]*)\)/g)
      } else if (ext === '.py') {
        outputPatterns.push(/print\s*\(([^)]*)\)/g)
      } else if (ext === '.sh') {
        outputPatterns.push(/echo\s+(.+)/g)
      }

      for (const pattern of outputPatterns) {
        const matches = [...code.matchAll(pattern)]
        if (matches.length > 0) {
          result.hasOutputStatements = true
          result.outputStatements.push(...matches.map(m => m[0]))

          // Try to extract the expected output from string literals in print statements
          for (const match of matches) {
            const fullMatch = match[0]
            // Extract string literals from the print statement
            const stringLiterals = [...fullMatch.matchAll(/['"`]([^'"`]+)['"`]/g)]
            for (const lit of stringLiterals) {
              if (lit[1] && lit[1].length > 1) {
                result.expectedOutput = (result.expectedOutput ? result.expectedOutput + '\n' : '') + lit[1]
              }
            }
          }
        }
      }
    } catch {
      // ignore
    }
  }

  // Also try to extract expected output from the task prompt
  if (!result.expectedOutput && taskPrompt) {
    // Look for quoted strings in the prompt that might be the expected output
    const quotedStrings = [...taskPrompt.matchAll(/["']([^"']+)["']/g)]
    if (quotedStrings.length > 0) {
      result.expectedOutput = quotedStrings.map(m => m[1]).join(' ')
    }

    // Look for "prints X", "says X", "outputs X", "displays X" patterns
    const outputPhrases = taskPrompt.match(/(?:prints?|says?|outputs?|displays?|logs?|writes?)\s+["']?([^"'\n.!]+)["']?/i)
    if (outputPhrases) {
      result.expectedOutput = outputPhrases[1].trim()
    }
  }

  return result
}

// ── Variable Extraction (fallback for scripts with no print statements) ──

function extractVariableValues(projectDir: string, file: string): string {
  try {
    const filePath = join(projectDir, file)
    const code = readFileSync(filePath, 'utf-8')
    const ext = extname(file).toLowerCase()

    if (!['.js', '.mjs', '.cjs'].includes(ext)) return ''

    // Try require() first for module exports
    try {
      const reqCmd = `node -e "const r = require('./${file}'); const s = typeof r === 'object' ? JSON.stringify(r) : String(r); if (s && s !== '{}' && s !== 'undefined') console.log(s)" 2>&1`
      const out = execSync(reqCmd, { cwd: projectDir, encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }).trim()
      if (out) return out
    } catch { /* ignore */ }

    // Extract top-level variable names and print their values
    const varNames = [...code.matchAll(/(?:let|const|var)\s+(\w+)\s*=/g)].map(m => m[1])
    if (varNames.length > 0) {
      const safeCode = code.replace(/"/g, '\\"').replace(/\n/g, '; ')
      const printVars = varNames.map(v =>
        `if (typeof ${v} !== 'undefined') console.log(${v})`
      ).join('; ')
      const evalCmd = `node -e "${safeCode}; ${printVars}" 2>&1`
      return execSync(evalCmd, { cwd: projectDir, encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] }).trim()
    }
  } catch {
    // ignore
  }
  return ''
}

// ── Output Verification ──────────────────────────────────────

interface VerificationResult {
  match: boolean | null
  confidence: number
  reasoning: string
}

function verifyOutput(stdout: string, taskPrompt: string | undefined, source: SourceAnalysis): VerificationResult {
  // Case 1: Code has print statements and produced output
  if (source.hasOutputStatements && stdout) {
    // Check if the output matches what we expected from the source
    if (source.expectedOutput) {
      const normalizedExpected = source.expectedOutput.toLowerCase().trim()
      const normalizedActual = stdout.toLowerCase().trim()

      if (normalizedActual.includes(normalizedExpected) || normalizedExpected.includes(normalizedActual)) {
        return {
          match: true,
          confidence: 100,
          reasoning: `Output verified — expected "${source.expectedOutput}", got "${stdout}"`
        }
      }
    }

    // Check if output matches keywords from the task prompt
    if (taskPrompt) {
      const promptKeywords = extractKeywords(taskPrompt)
      const matchedKeywords = promptKeywords.filter(kw => stdout.toLowerCase().includes(kw.toLowerCase()))

      if (matchedKeywords.length > 0 && matchedKeywords.length >= promptKeywords.length * 0.5) {
        return {
          match: true,
          confidence: 90,
          reasoning: `Output matches task — found "${matchedKeywords.join('", "')}" in output: "${stdout}"`
        }
      }
    }

    // Code ran and produced output but we can't verify it matches
    return {
      match: null,
      confidence: 80,
      reasoning: `Code ran and produced output: "${stdout.slice(0, 100)}" — could not verify against task`
    }
  }

  // Case 2: Code has print statements but NO output
  if (source.hasOutputStatements && !stdout) {
    return {
      match: false,
      confidence: 40,
      reasoning: `Code has output statements (${source.outputStatements[0]}) but produced no output — possible logic error`
    }
  }

  // Case 3: Code has no print statements (agent didn't add console.log)
  if (!source.hasOutputStatements) {
    if (stdout) {
      // We extracted variable values — check if they match
      if (taskPrompt) {
        const promptKeywords = extractKeywords(taskPrompt)
        const matchedKeywords = promptKeywords.filter(kw => stdout.toLowerCase().includes(kw.toLowerCase()))
        if (matchedKeywords.length > 0) {
          return {
            match: true,
            confidence: 75,
            reasoning: `No print statements, but variable values contain "${matchedKeywords.join('", "')}" — matches task`
          }
        }
      }
      return {
        match: null,
        confidence: 70,
        reasoning: `Code has no output statements. Variable values: "${stdout.slice(0, 100)}"`
      }
    }

    // No output statements and no output at all
    return {
      match: null,
      confidence: 65,
      reasoning: 'Code ran without errors but has no output statements — cannot verify result'
    }
  }

  // Fallback
  return {
    match: null,
    confidence: 70,
    reasoning: `Code executed successfully${stdout ? ': ' + stdout.slice(0, 100) : ' with no output'}`
  }
}

/**
 * Extract meaningful keywords from a task prompt.
 * Filters out common filler words to get the actual expected content.
 */
function extractKeywords(prompt: string): string[] {
  const stopWords = new Set([
    'a', 'an', 'the', 'is', 'it', 'in', 'to', 'of', 'and', 'or', 'that', 'this',
    'for', 'with', 'on', 'at', 'by', 'from', 'as', 'be', 'was', 'are', 'were',
    'create', 'make', 'build', 'write', 'add', 'file', 'code', 'program', 'script',
    'called', 'named', 'prints', 'print', 'says', 'outputs', 'displays', 'logs',
    'should', 'will', 'can', 'do', 'does', 'has', 'have', 'just', 'also',
    'please', 'i', 'want', 'you', 'me', 'my', 'your', 'we', 'us', 'our',
    'hello', // keep below — we extract quoted strings separately
  ])

  // First, extract quoted strings as exact phrases (highest signal)
  const quotedPhrases = [...prompt.matchAll(/["']([^"']+)["']/g)].map(m => m[1])

  // Then extract individual meaningful words
  const words = prompt
    .replace(/["'][^"']+["']/g, '') // remove quoted strings already captured
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !stopWords.has(w))

  // Quoted phrases are the strongest signal — prioritize them
  return [...quotedPhrases, ...words].filter(Boolean)
}

// ── Execution Target Detection ──────────────────────────────

interface ExecutionTarget {
  command: string
  type: string
}

function pickExecutionTarget(projectDir: string, changedFiles: string[]): ExecutionTarget | null {
  // Check if there's a package.json with a start script
  const pkgPath = join(projectDir, 'package.json')
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
      if (pkg.scripts?.start && !isLongRunning(pkg.scripts.start)) {
        return { command: 'npm start 2>&1', type: 'npm' }
      }
    } catch {
      // ignore
    }
  }

  // Look at changed files for something we can run directly
  for (const file of changedFiles) {
    const ext = extname(file).toLowerCase()
    const fullPath = join(projectDir, file)

    if (!existsSync(fullPath)) continue

    switch (ext) {
      case '.js':
      case '.mjs':
      case '.cjs':
        return { command: `node "${file}" 2>&1`, type: 'node' }

      case '.ts':
        if (commandExists('tsx')) {
          return { command: `npx tsx "${file}" 2>&1`, type: 'tsx' }
        }
        return { command: `npx tsc --noEmit "${file}" 2>&1`, type: 'tsc' }

      case '.py':
        return { command: `python3 "${file}" 2>&1`, type: 'python' }

      case '.sh':
        return { command: `bash "${file}" 2>&1`, type: 'bash' }

      case '.html':
        return { command: `cat "${file}" | head -1`, type: 'html-check' }

      case '.json':
        return { command: `node -e "JSON.parse(require('fs').readFileSync('${file}','utf-8')); console.log('Valid JSON')" 2>&1`, type: 'json-check' }
    }
  }

  // Last resort: look for any .js file in the project root
  try {
    const files = readdirSync(projectDir)
    const jsFile = files.find((f) => f.endsWith('.js') && !f.startsWith('.'))
    if (jsFile) {
      return { command: `node "${jsFile}" 2>&1`, type: 'node' }
    }
  } catch {
    // ignore
  }

  return null
}

function isLongRunning(script: string): boolean {
  const patterns = [
    /\bnodemon\b/, /\bnext\s+dev\b/, /\bnext\s+start\b/,
    /\bvite\b/, /\bwebpack\s+serve\b/, /\breact-scripts\s+start\b/,
    /\bexpress\b/, /\bserver\b/, /\blisten\b/, /\bwatch\b/,
    /--watch/, /--serve/
  ]
  return patterns.some((p) => p.test(script))
}

function analyzeError(output: string, exitCode: number): { confidence: number; reasoning: string } {
  const lower = output.toLowerCase()

  if (lower.includes('syntaxerror') || lower.includes('unexpected token') || lower.includes('syntax error')) {
    return { confidence: 15, reasoning: `Syntax error: ${output.slice(0, 150)}` }
  }

  if (lower.includes('cannot find module') || lower.includes('module not found') || lower.includes('no such file')) {
    return { confidence: 40, reasoning: `Missing module/file: ${output.slice(0, 150)}` }
  }

  if (lower.includes('typeerror') || lower.includes('referenceerror')) {
    return { confidence: 25, reasoning: `Runtime error: ${output.slice(0, 150)}` }
  }

  return { confidence: 30, reasoning: `Execution failed (exit ${exitCode}): ${output.slice(0, 150)}` }
}

function commandExists(cmd: string): boolean {
  try {
    execSync(`which ${cmd}`, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] })
    return true
  } catch {
    return false
  }
}
