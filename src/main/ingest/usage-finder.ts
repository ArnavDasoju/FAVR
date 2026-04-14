/**
 * Usage Finder — for each vulnerability's package, locate concrete
 * import/require/use sites in the project's source files.
 *
 * After OSV has told us "express@4.18.2 has CVE-2024-XXXX", this module
 * walks each affected service's directory and records every file:line
 * where that package is imported. The hits are attached to the
 * vulnerability object so agents get exact targets instead of just a
 * manifest to update.
 */

import { readdirSync, readFileSync, statSync } from 'fs'
import { join, relative, basename } from 'path'
import type { Vulnerability, CodeUsage } from '../engine/types'

type Ecosystem = 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'Maven' | 'RubyGems'

interface ServiceLite {
  id: string
  path: string        // relative to project root
  ecosystem: Ecosystem
}

const MAX_USAGES_PER_VULN = 20
const MAX_FILE_BYTES = 512 * 1024     // 512KB — skip larger files (minified bundles, generated)
const MAX_FILES_PER_SERVICE = 2000    // safety cap per service directory walk

const IGNORED_DIRS = new Set([
  'node_modules', '.git', 'dist', 'out', 'build', '.next', '.nuxt',
  '__pycache__', '.venv', 'venv', 'env', '.tox', 'target',
  'vendor', '.idea', '.vscode', '.cache', 'coverage', '.turbo',
  '.output', 'tmp', '.tmp', '.expo', '.yarn', '.pnpm-store'
])

// Source-file extensions per ecosystem. Only files with these extensions are scanned.
const EXTENSIONS: Record<Ecosystem, string[]> = {
  npm:        ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte'],
  PyPI:       ['.py', '.pyi'],
  Go:         ['.go'],
  'crates.io':['.rs'],
  Maven:      ['.java', '.kt', '.scala', '.groovy'],
  RubyGems:   ['.rb', '.rake', '.gemspec']
}

/**
 * Find all import/usage sites in the project for each vulnerability.
 * Mutates the vuln objects in place to attach `usageLocations`.
 */
export function findUsageLocations(
  projectDir: string,
  services: ServiceLite[],
  vulnerabilities: Vulnerability[],
  onProgress?: (pct: number, msg: string) => void
): void {
  if (vulnerabilities.length === 0 || services.length === 0) return

  // Index services by id for fast lookup
  const serviceById = new Map<string, ServiceLite>()
  for (const s of services) serviceById.set(s.id, s)

  // Group vulnerabilities by the service they affect, per ecosystem.
  // For each service we walk its directory ONCE and match all relevant vulns in parallel.
  const vulnsByService = new Map<string, Vulnerability[]>()
  for (const vuln of vulnerabilities) {
    for (const svcId of vuln.affectedServiceIds) {
      if (!vulnsByService.has(svcId)) vulnsByService.set(svcId, [])
      vulnsByService.get(svcId)!.push(vuln)
    }
  }

  let done = 0
  const total = vulnsByService.size

  for (const [svcId, svcVulns] of vulnsByService) {
    const service = serviceById.get(svcId)
    if (!service) { done++; continue }

    const exts = EXTENSIONS[service.ecosystem]
    if (!exts) { done++; continue }

    // Build matchers for each vuln. Each matcher: { vuln, test(line) -> boolean }
    const matchers: { vuln: Vulnerability; patterns: RegExp[]; symbol: string }[] = []
    for (const vuln of svcVulns) {
      const [pkgName] = vuln.affectedPackage.split('@')
      if (!pkgName) continue
      const patterns = buildPatterns(pkgName, service.ecosystem)
      if (patterns.length === 0) continue
      matchers.push({ vuln, patterns, symbol: pkgName })
    }

    if (matchers.length === 0) { done++; continue }

    // Walk the service directory
    const absServiceDir = join(projectDir, service.path || '.')
    scanDirectory(absServiceDir, projectDir, exts, (filePath, lines) => {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (line.length > 400) continue  // skip huge lines
        for (const m of matchers) {
          if (m.vuln.usageLocations && m.vuln.usageLocations.length >= MAX_USAGES_PER_VULN) continue
          for (const rx of m.patterns) {
            if (rx.test(line)) {
              if (!m.vuln.usageLocations) m.vuln.usageLocations = []
              m.vuln.usageLocations.push({
                file: relative(projectDir, filePath).replace(/\\/g, '/'),
                line: i + 1,
                snippet: line.trim().slice(0, 200),
                symbol: m.symbol
              })
              break  // stop checking remaining patterns for this vuln on this line
            }
          }
        }
      }
    })

    done++
    if (onProgress) onProgress(Math.round((done / total) * 100), `Located usages for ${done}/${total} services`)
  }
}

/**
 * Build regex patterns to match imports/usages of a package, per ecosystem.
 * Patterns are intentionally conservative — they target import statements,
 * not arbitrary mentions in comments.
 */
function buildPatterns(pkgName: string, ecosystem: Ecosystem): RegExp[] {
  const esc = pkgName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

  switch (ecosystem) {
    case 'npm':
      // ES imports, CommonJS require, dynamic import — match package name or scoped subpath
      return [
        new RegExp(`\\bfrom\\s+['"]${esc}(['"]|/)`),           // import X from 'pkg' or 'pkg/sub'
        new RegExp(`\\bimport\\s+['"]${esc}(['"]|/)`),          // import 'pkg'
        new RegExp(`\\brequire\\s*\\(\\s*['"]${esc}(['"]|/)`),  // require('pkg')
        new RegExp(`\\bimport\\s*\\(\\s*['"]${esc}(['"]|/)`)    // dynamic import('pkg')
      ]

    case 'PyPI': {
      // Python: "import pkg", "from pkg import ...", "from pkg.sub import ..."
      // Normalize: PyPI package names use hyphens but import names use underscores
      const importName = pkgName.replace(/-/g, '_')
      const impEsc = importName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      return [
        new RegExp(`^\\s*import\\s+${impEsc}(\\s|\\.|$)`),
        new RegExp(`^\\s*from\\s+${impEsc}(\\s|\\.)`)
      ]
    }

    case 'Go':
      // Go imports use the full module path: `"github.com/owner/repo"` or grouped imports
      return [
        new RegExp(`["']${esc}["']`),                          // full import path in quotes
      ]

    case 'crates.io':
      // Rust: `use cratename::...` or `extern crate cratename`
      // Rust crate names with hyphens become underscores in `use` statements
      const useName = pkgName.replace(/-/g, '_')
      const useEsc = useName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      return [
        new RegExp(`\\buse\\s+${useEsc}(::|\\s|;)`),
        new RegExp(`\\bextern\\s+crate\\s+${useEsc}\\b`)
      ]

    case 'Maven':
      // Maven artifact != Java package, so best we can do is search for the artifactId
      // appearing in import statements. Gives false negatives but few false positives.
      return [
        new RegExp(`\\bimport\\s+[\\w.]*${esc}[\\w.]*\\s*;`, 'i')
      ]

    case 'RubyGems':
      return [
        new RegExp(`\\brequire\\s+['"]${esc}['"]`),
        new RegExp(`\\brequire_relative\\s+['"]${esc}['"]`)
      ]

    default:
      return []
  }
}

/**
 * Recursively walk a directory, calling `onFile` for each source file
 * whose extension matches. Skips ignored dirs and oversized files.
 */
function scanDirectory(
  root: string,
  projectRoot: string,
  exts: string[],
  onFile: (filePath: string, lines: string[]) => void
): void {
  let filesProcessed = 0
  const visited = new Set<string>()

  function walk(dir: string): void {
    if (filesProcessed >= MAX_FILES_PER_SERVICE) return
    if (visited.has(dir)) return
    visited.add(dir)

    let entries: string[]
    try {
      entries = readdirSync(dir)
    } catch {
      return
    }

    for (const name of entries) {
      if (filesProcessed >= MAX_FILES_PER_SERVICE) return
      if (IGNORED_DIRS.has(name) || name.startsWith('.')) continue

      const full = join(dir, name)
      let stat
      try { stat = statSync(full) } catch { continue }

      if (stat.isDirectory()) {
        walk(full)
      } else if (stat.isFile()) {
        // Extension filter
        const lowerName = name.toLowerCase()
        if (!exts.some(ext => lowerName.endsWith(ext))) continue
        if (stat.size > MAX_FILE_BYTES) continue

        let content: string
        try {
          content = readFileSync(full, 'utf-8')
        } catch {
          continue
        }

        const lines = content.split('\n')
        onFile(full, lines)
        filesProcessed++
      }
    }
  }

  try {
    const stat = statSync(root)
    if (stat.isDirectory()) {
      walk(root)
    }
  } catch {
    // Service directory gone — nothing to scan
  }
  // Suppress unused-var warning if projectRoot ever gets used for relative pathing here
  void projectRoot
  void basename
}
