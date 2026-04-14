/**
 * Codebase Scanner — cross-references parsed CVEs against actual project code.
 * Checks package.json, requirements.txt, go.mod, etc. for vulnerable versions.
 */

import { existsSync, readFileSync, readdirSync } from 'fs'
import { join, basename } from 'path'
import type { Vulnerability } from '../engine/types.js'

export interface ScanResult {
  cveId: string
  found: boolean
  files: ScanMatch[]
  currentVersion: string | null
  vulnerableVersion: string | null
}

export interface ScanMatch {
  file: string
  line: number
  content: string
  matchType: 'package-version' | 'import' | 'config' | 'code-pattern'
}

/**
 * Scan a codebase directory for vulnerabilities.
 */
export function scanCodebase(
  projectDir: string,
  vulnerabilities: Vulnerability[]
): ScanResult[] {
  const results: ScanResult[] = []

  // Read dependency files
  const packageJson = readJsonFile(join(projectDir, 'package.json'))
  const packageLock = readJsonFile(join(projectDir, 'package-lock.json'))
  const goMod = readTextFile(join(projectDir, 'go.mod'))
  const requirements = readTextFile(join(projectDir, 'requirements.txt'))
  const goSum = readTextFile(join(projectDir, 'go.sum'))

  for (const vuln of vulnerabilities) {
    const result: ScanResult = {
      cveId: vuln.cveId,
      found: false,
      files: [],
      currentVersion: null,
      vulnerableVersion: vuln.affectedPackage
    }

    // Extract package name and version from affectedPackage (e.g. "express@4.18.2")
    const [pkgName, pkgVersion] = parsePackageSpec(vuln.affectedPackage)

    // Check Node.js dependencies
    if (packageJson) {
      const allDeps = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies
      }

      if (allDeps[pkgName]) {
        const installedVersion = allDeps[pkgName].replace(/[\^~>=<]/g, '')
        result.currentVersion = installedVersion
        result.found = true
        result.files.push({
          file: 'package.json',
          line: findLineInFile(join(projectDir, 'package.json'), pkgName),
          content: `"${pkgName}": "${allDeps[pkgName]}"`,
          matchType: 'package-version'
        })
      }
    }

    // Check Go modules
    if (goMod && pkgName.includes('/')) {
      const lines = goMod.split('\n')
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(pkgName)) {
          result.found = true
          const versionMatch = lines[i].match(/v[\d.]+/)
          result.currentVersion = versionMatch?.[0] ?? null
          result.files.push({
            file: 'go.mod',
            line: i + 1,
            content: lines[i].trim(),
            matchType: 'package-version'
          })
        }
      }
    }

    // Check Python requirements
    if (requirements && !pkgName.includes('/')) {
      const lines = requirements.split('\n')
      for (let i = 0; i < lines.length; i++) {
        const lower = lines[i].toLowerCase()
        if (lower.startsWith(pkgName.toLowerCase())) {
          result.found = true
          const versionMatch = lines[i].match(/==(.+)/)
          result.currentVersion = versionMatch?.[1] ?? null
          result.files.push({
            file: 'requirements.txt',
            line: i + 1,
            content: lines[i].trim(),
            matchType: 'package-version'
          })
        }
      }
    }

    // Scan source files for imports of the vulnerable package
    if (!result.found) {
      const importMatches = scanForImports(projectDir, pkgName)
      if (importMatches.length > 0) {
        result.found = true
        result.files.push(...importMatches)
      }
    }

    results.push(result)
  }

  return results
}

/**
 * Scan source files for imports of a specific package.
 */
function scanForImports(projectDir: string, packageName: string, maxDepth = 3): ScanMatch[] {
  const matches: ScanMatch[] = []
  const extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go']

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return
    try {
      const entries = readdirSync(dir, { withFileTypes: true })
      for (const entry of entries) {
        if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'out') continue
        const fullPath = join(dir, entry.name)
        if (entry.isDirectory()) {
          walk(fullPath, depth + 1)
        } else if (extensions.some(ext => entry.name.endsWith(ext))) {
          try {
            const content = readFileSync(fullPath, 'utf-8')
            const lines = content.split('\n')
            for (let i = 0; i < lines.length; i++) {
              if (lines[i].includes(packageName) &&
                  (lines[i].includes('import') || lines[i].includes('require') || lines[i].includes('from'))) {
                matches.push({
                  file: fullPath.replace(projectDir + '/', ''),
                  line: i + 1,
                  content: lines[i].trim(),
                  matchType: 'import'
                })
              }
            }
          } catch { /* skip unreadable files */ }
        }
      }
    } catch { /* skip unreadable dirs */ }
  }

  walk(projectDir, 0)
  return matches.slice(0, 10) // cap at 10 matches
}

function parsePackageSpec(spec: string): [string, string | null] {
  const atIdx = spec.lastIndexOf('@')
  if (atIdx > 0) {
    return [spec.slice(0, atIdx), spec.slice(atIdx + 1)]
  }
  return [spec, null]
}

function readJsonFile(path: string): any | null {
  try {
    if (!existsSync(path)) return null
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch { return null }
}

function readTextFile(path: string): string | null {
  try {
    if (!existsSync(path)) return null
    return readFileSync(path, 'utf-8')
  } catch { return null }
}

function findLineInFile(path: string, search: string): number {
  try {
    const lines = readFileSync(path, 'utf-8').split('\n')
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(search)) return i + 1
    }
  } catch { /* ignore */ }
  return 1
}
