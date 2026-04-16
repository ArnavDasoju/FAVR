/**
 * Deterministic dependency-manifest patcher.
 *
 * Most CVE fixes are "bump package X from A to B in the lockfile" — that's
 * a mechanical string edit, not a reasoning task. Asking an LLM to regurgitate
 * a 400-line package.json with one version changed is slow, expensive, and
 * often mangles JSON formatting or drops sibling deps. This module does the
 * edit directly so the LLM path becomes a fallback for genuine code changes.
 *
 * Supported manifests:
 *   - package.json (Node)
 *   - requirements.txt (Python)
 *   - pyproject.toml (Python / Poetry)
 *   - go.mod (Go)
 *   - Cargo.toml (Rust)
 *   - Gemfile (Ruby)
 */

import { readFileSync, writeFileSync, statSync } from 'fs'
import { join, relative, sep } from 'path'
import { readdirSync } from 'fs'

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', '.next', '.turbo',
  'vendor', 'target', '__pycache__', '.venv', 'venv', '.cache',
  'coverage', '.nuxt', '.svelte-kit', 'out'
])

const MANIFEST_NAMES = new Set([
  'package.json',
  'requirements.txt',
  'pyproject.toml',
  'go.mod',
  'Cargo.toml',
  'Gemfile'
])

export interface ManifestPatchResult {
  success: boolean
  changedFiles: string[]
  reason?: string
}

/**
 * Attempt to deterministically patch a vulnerability by bumping the package
 * version in whatever manifest(s) declare it. Returns `success: false` if we
 * couldn't find a matching manifest — caller should then fall back to the LLM.
 */
export function patchManifest(
  projectDir: string,
  packageName: string,
  targetVersion: string
): ManifestPatchResult {
  if (!packageName || !targetVersion) {
    return { success: false, changedFiles: [], reason: 'missing package name or target version' }
  }

  const manifests = findManifests(projectDir)
  const changed: string[] = []

  for (const absPath of manifests) {
    const name = absPath.split(sep).pop()!
    try {
      const before = readFileSync(absPath, 'utf-8')
      let after: string | null = null

      if (name === 'package.json') {
        after = patchPackageJson(before, packageName, targetVersion)
      } else if (name === 'requirements.txt') {
        after = patchRequirementsTxt(before, packageName, targetVersion)
      } else if (name === 'pyproject.toml') {
        after = patchPyprojectToml(before, packageName, targetVersion)
      } else if (name === 'go.mod') {
        after = patchGoMod(before, packageName, targetVersion)
      } else if (name === 'Cargo.toml') {
        after = patchCargoToml(before, packageName, targetVersion)
      } else if (name === 'Gemfile') {
        after = patchGemfile(before, packageName, targetVersion)
      }

      if (after !== null && after !== before) {
        writeFileSync(absPath, after, 'utf-8')
        changed.push(relative(projectDir, absPath))
      }
    } catch (err) {
      console.warn(`[manifest-patcher] Failed on ${absPath}:`, err)
    }
  }

  if (changed.length === 0) {
    return { success: false, changedFiles: [], reason: `no manifest declared "${packageName}"` }
  }
  return { success: true, changedFiles: changed }
}

// ─── Manifest discovery ──────────────────────────────────────────────────

function findManifests(root: string): string[] {
  const results: string[] = []
  walk(root, results, 0)
  return results
}

function walk(dir: string, out: string[], depth: number) {
  if (depth > 6) return
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return
  }
  for (const entry of entries) {
    if (entry.startsWith('.') && entry !== '.env') continue
    if (SKIP_DIRS.has(entry)) continue
    const full = join(dir, entry)
    let st
    try {
      st = statSync(full)
    } catch {
      continue
    }
    if (st.isDirectory()) {
      walk(full, out, depth + 1)
    } else if (MANIFEST_NAMES.has(entry)) {
      out.push(full)
    }
  }
}

// ─── Per-format patchers ────────────────────────────────────────────────

function patchPackageJson(content: string, pkg: string, version: string): string | null {
  let parsed: any
  try {
    parsed = JSON.parse(content)
  } catch {
    return null
  }

  let touched = false
  const sections = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']
  for (const section of sections) {
    if (parsed[section] && typeof parsed[section] === 'object' && pkg in parsed[section]) {
      parsed[section][pkg] = version
      touched = true
    }
  }
  if (!touched) return null

  // Preserve trailing newline + indentation of the original file where possible.
  const indent = detectIndent(content)
  const endsWithNewline = content.endsWith('\n')
  return JSON.stringify(parsed, null, indent) + (endsWithNewline ? '\n' : '')
}

function detectIndent(json: string): number | string {
  const match = json.match(/\n([ \t]+)"/)
  if (!match) return 2
  const ws = match[1]
  if (ws.startsWith('\t')) return '\t'
  return ws.length
}

function patchRequirementsTxt(content: string, pkg: string, version: string): string | null {
  const lines = content.split('\n')
  const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // Match: pkg==1.2.3 | pkg>=1.0 | pkg~=1.0 | pkg (with optional extras "pkg[foo]")
  const re = new RegExp(`^(\\s*${escaped}(?:\\[[^\\]]+\\])?)\\s*(==|>=|<=|~=|!=|<|>)?.*$`, 'i')
  let touched = false
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    if (raw.trim().startsWith('#')) continue
    const m = raw.match(re)
    if (m) {
      lines[i] = `${m[1]}==${version}`
      touched = true
    }
  }
  return touched ? lines.join('\n') : null
}

function patchPyprojectToml(content: string, pkg: string, version: string): string | null {
  const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // Poetry: under [tool.poetry.dependencies] or [tool.poetry.dev-dependencies]
  // Entry forms:  foo = "1.2.3"  |  foo = "^1.2.3"  |  foo = { version = "1.2.3", ... }
  const keyVal = new RegExp(`^(\\s*${escaped}\\s*=\\s*")[^"]*(")`, 'm')
  const inlineTable = new RegExp(`^(\\s*${escaped}\\s*=\\s*\\{[^}]*version\\s*=\\s*")[^"]*(")`, 'm')
  // PEP 621: dependencies = ["foo>=1.2.3", ...]
  const pep621 = new RegExp(`(["']${escaped}(?:\\[[^\\]]+\\])?)\\s*(?:==|>=|<=|~=|!=|<|>)[^"']*(["'])`, 'g')

  let out = content
  let touched = false
  if (inlineTable.test(out)) {
    out = out.replace(inlineTable, `$1${version}$2`)
    touched = true
  } else if (keyVal.test(out)) {
    out = out.replace(keyVal, `$1${version}$2`)
    touched = true
  }
  if (pep621.test(content)) {
    out = out.replace(pep621, `$1==${version}$2`)
    touched = true
  }
  return touched ? out : null
}

function patchGoMod(content: string, pkg: string, version: string): string | null {
  const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // Line forms inside require() block or bare: "    modulepath v1.2.3"
  const re = new RegExp(`^(\\s*${escaped})\\s+v?[\\w.\\-+]+(\\s*(?://.*)?)$`, 'gm')
  if (!re.test(content)) return null
  // Go versions canonically start with 'v'
  const v = version.startsWith('v') ? version : `v${version}`
  return content.replace(re, `$1 ${v}$2`)
}

function patchCargoToml(content: string, pkg: string, version: string): string | null {
  const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const keyVal = new RegExp(`^(\\s*${escaped}\\s*=\\s*")[^"]*(")`, 'm')
  const inlineTable = new RegExp(`^(\\s*${escaped}\\s*=\\s*\\{[^}]*version\\s*=\\s*")[^"]*(")`, 'm')
  let out = content
  let touched = false
  if (inlineTable.test(out)) {
    out = out.replace(inlineTable, `$1${version}$2`)
    touched = true
  } else if (keyVal.test(out)) {
    out = out.replace(keyVal, `$1${version}$2`)
    touched = true
  }
  return touched ? out : null
}

function patchGemfile(content: string, pkg: string, version: string): string | null {
  const escaped = pkg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // gem "foo", "~> 1.2.3"   |   gem 'foo', '1.2.3'
  const re = new RegExp(`(gem\\s+['"]${escaped}['"]\\s*,\\s*['"])[^'"]*(['"])`, 'g')
  if (!re.test(content)) return null
  return content.replace(re, `$1${version}$2`)
}
