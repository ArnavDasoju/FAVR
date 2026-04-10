/**
 * Codebase Analyzer — automatically discovers services, dependencies, and
 * vulnerabilities from a real project directory.
 *
 * Three-phase pipeline:
 *   Phase 1: Service Discovery — scan for manifests (package.json, go.mod, etc.)
 *   Phase 2: Dependency Discovery — infer inter-service relationships
 *   Phase 3: Vulnerability Discovery — query OSV.dev for known CVEs
 *
 * Output: { services, dependencies, vulnerabilities } ready for runAnalysis()
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'fs'
import { join, basename, relative, dirname } from 'path'
import { net } from 'electron'
import type {
  Service, Dependency, Vulnerability, Severity,
  ComplianceFramework, MaintenanceWindow
} from '../engine/types'

// ─── Public Types ─────────────────────────────────────────────

export interface CodebaseAnalysisResult {
  services: Service[]
  dependencies: Dependency[]
  vulnerabilities: Vulnerability[]
  stats: {
    servicesFound: number
    packagesScanned: number
    vulnerabilitiesFound: number
    ecosystems: string[]
  }
}

export type AnalyzerProgressCallback = (progress: {
  phase: string
  progress: number
  message: string
}) => void

// ─── Internal Types ───────────────────────────────────────────

interface DiscoveredService {
  id: string
  name: string
  path: string              // relative to project root
  ecosystem: Ecosystem
  packages: DiscoveredPackage[]
  techStack: string[]
  hasDockerfile: boolean
  envVars: Record<string, string>
}

interface DiscoveredPackage {
  name: string
  version: string
  ecosystem: Ecosystem
  isDev: boolean
}

type Ecosystem = 'npm' | 'PyPI' | 'Go' | 'crates.io' | 'Maven' | 'RubyGems'

interface OsvVuln {
  id: string
  aliases: string[]
  summary: string
  details: string
  severity: { type: string; score: string }[]
  affected: {
    package: { ecosystem: string; name: string }
    ranges: { type: string; events: { introduced?: string; fixed?: string }[] }[]
    versions?: string[]
    database_specific?: any
  }[]
  database_specific?: { severity?: string; cwe_ids?: string[] }
  references: { type: string; url: string }[]
}

// ─── Main Entry Point ─────────────────────────────────────────

/**
 * Analyze a codebase directory and produce engine-ready input.
 */
export async function analyzeCodebase(
  projectDir: string,
  onProgress?: AnalyzerProgressCallback
): Promise<CodebaseAnalysisResult> {
  if (!existsSync(projectDir)) {
    throw new Error(`Directory not found: ${projectDir}`)
  }

  // Phase 1: Discover services
  onProgress?.({ phase: 'discovery', progress: 0, message: 'Scanning for services and packages...' })
  const discovered = discoverServices(projectDir)
  onProgress?.({
    phase: 'discovery',
    progress: 100,
    message: `Found ${discovered.length} service(s): ${discovered.map(s => s.name).join(', ')}`
  })

  if (discovered.length === 0) {
    throw new Error(
      'No services found. Make sure the directory contains package.json, go.mod, requirements.txt, Cargo.toml, pom.xml, or Gemfile.'
    )
  }

  // Phase 2: Discover dependencies
  onProgress?.({ phase: 'dependencies', progress: 0, message: 'Inferring inter-service dependencies...' })
  const dependencies = discoverDependencies(projectDir, discovered)
  onProgress?.({
    phase: 'dependencies',
    progress: 100,
    message: `Found ${dependencies.length} dependency relationship(s)`
  })

  // Phase 3: Discover vulnerabilities
  const allPackages = discovered.flatMap(s => s.packages.filter(p => !p.isDev))
  onProgress?.({ phase: 'vulnerabilities', progress: 0, message: `Querying OSV.dev for ${allPackages.length} packages...` })

  const vulnerabilities = await discoverVulnerabilities(discovered, (pct, msg) => {
    onProgress?.({ phase: 'vulnerabilities', progress: pct, message: msg })
  })

  onProgress?.({
    phase: 'vulnerabilities',
    progress: 100,
    message: `Found ${vulnerabilities.length} known vulnerabilities`
  })

  // Convert discovered services to engine Service type
  const services = discovered.map(d => toEngineService(d))

  const ecosystems = [...new Set(discovered.map(d => d.ecosystem))]

  return {
    services,
    dependencies,
    vulnerabilities,
    stats: {
      servicesFound: services.length,
      packagesScanned: allPackages.length,
      vulnerabilitiesFound: vulnerabilities.length,
      ecosystems
    }
  }
}

// ─── Phase 1: Service Discovery ───────────────────────────────

/**
 * Walk the project tree and discover services by their manifest files.
 * Handles monorepos (packages/, services/, apps/ directories).
 */
function discoverServices(projectDir: string): DiscoveredService[] {
  const services: DiscoveredService[] = []
  const visited = new Set<string>()

  // Patterns that indicate a service root
  const manifestFiles = [
    'package.json',
    'go.mod',
    'requirements.txt',
    'Pipfile',
    'pyproject.toml',
    'setup.py',
    'Cargo.toml',
    'pom.xml',
    'build.gradle',
    'Gemfile'
  ]

  function walk(dir: string, depth: number) {
    if (depth > 5) return
    if (visited.has(dir)) return
    visited.add(dir)

    const dirName = basename(dir)

    // Skip common non-service directories
    if (shouldSkipDir(dirName)) return

    let names: string[]
    try {
      names = readdirSync(dir)
    } catch {
      return
    }

    const hasManifest = manifestFiles.some(m => names.includes(m))

    if (hasManifest) {
      const service = parseServiceFromDir(dir, projectDir)
      if (service && service.packages.length > 0) {
        services.push(service)
      }
      // Don't recurse into sub-node_modules etc, but DO recurse into
      // monorepo subdirs (packages/, apps/, services/) even from here
      for (const name of names) {
        if (isMonorepoDir(name)) {
          const full = join(dir, name)
          try { if (statSync(full).isDirectory()) walk(full, depth + 1) } catch { /* skip */ }
        }
      }
      return
    }

    // No manifest here — keep recursing
    for (const name of names) {
      if (shouldSkipDir(name)) continue
      const full = join(dir, name)
      try { if (statSync(full).isDirectory()) walk(full, depth + 1) } catch { /* skip */ }
    }
  }

  walk(projectDir, 0)

  // Fallback: if no manifest-based services found, check for source-file-only projects
  if (services.length === 0) {
    const fallback = parseSourceOnlyService(projectDir)
    if (fallback) {
      services.push(fallback)
    }
  }

  // Deduplicate services with identical paths
  const uniqueById = new Map<string, DiscoveredService>()
  for (const s of services) {
    uniqueById.set(s.id, s)
  }

  return Array.from(uniqueById.values())
}

/**
 * Fallback: detect a service from source files alone (no manifest).
 * Scans for .py/.js/.ts/.go files and extracts imports.
 */
function parseSourceOnlyService(dir: string): DiscoveredService | null {
  const sourceExts: Record<string, Ecosystem> = {
    '.py': 'PyPI',
    '.js': 'npm',
    '.ts': 'npm',
    '.go': 'Go',
    '.rs': 'crates.io',
    '.java': 'Maven',
    '.rb': 'RubyGems'
  }

  let names: string[]
  try {
    names = readdirSync(dir)
  } catch {
    return null
  }

  // Collect all source files (including one level of subdirs)
  const sourceFilesByEcosystem = new Map<Ecosystem, string[]>()
  for (const name of names) {
    if (shouldSkipDir(name)) continue
    const ext = Object.keys(sourceExts).find(e => name.endsWith(e))
    if (ext) {
      const eco = sourceExts[ext]
      const existing = sourceFilesByEcosystem.get(eco) ?? []
      existing.push(name)
      sourceFilesByEcosystem.set(eco, existing)
    } else {
      // Check one level deep for source files in subdirs
      const subPath = join(dir, name)
      try {
        if (statSync(subPath).isDirectory()) {
          const subNames = readdirSync(subPath)
          for (const subName of subNames) {
            const subExt = Object.keys(sourceExts).find(e => subName.endsWith(e))
            if (subExt) {
              const eco = sourceExts[subExt]
              const existing = sourceFilesByEcosystem.get(eco) ?? []
              existing.push(join(name, subName))
              sourceFilesByEcosystem.set(eco, existing)
            }
          }
        }
      } catch { /* skip */ }
    }
  }

  if (sourceFilesByEcosystem.size === 0) return null

  // Pick the dominant ecosystem (most source files)
  let dominantEco: Ecosystem = 'npm'
  let maxFiles = 0
  for (const [eco, files] of sourceFilesByEcosystem) {
    if (files.length > maxFiles) {
      maxFiles = files.length
      dominantEco = eco
    }
  }

  const projectName = basename(dir)
  const id = slugify(projectName)

  const service: DiscoveredService = {
    id,
    name: projectName,
    path: '.',
    ecosystem: dominantEco,
    packages: [],
    techStack: [],
    hasDockerfile: existsSync(join(dir, 'Dockerfile')),
    envVars: parseEnvFile(dir)
  }

  const sourceFiles = sourceFilesByEcosystem.get(dominantEco) ?? []

  if (dominantEco === 'PyPI') {
    service.techStack.push('Python')
    const imports = extractPythonImports(dir, sourceFiles)
    for (const imp of imports) {
      service.packages.push({ name: imp, version: '0.0.0', ecosystem: 'PyPI', isDev: false })
      service.techStack.push(imp)
    }
  } else if (dominantEco === 'npm') {
    service.techStack.push('JavaScript')
    const imports = extractJsImports(dir, sourceFiles)
    for (const imp of imports) {
      service.packages.push({ name: imp, version: '0.0.0', ecosystem: 'npm', isDev: false })
      service.techStack.push(imp)
    }
  } else if (dominantEco === 'Go') {
    service.techStack.push('Go')
  } else if (dominantEco === 'crates.io') {
    service.techStack.push('Rust')
  } else if (dominantEco === 'Maven') {
    service.techStack.push('Java')
  } else if (dominantEco === 'RubyGems') {
    service.techStack.push('Ruby')
  }

  // Always return the service even without packages — it's a valid project
  return service
}

/**
 * Extract third-party import names from Python files.
 * Filters out standard library modules.
 */
function extractPythonImports(dir: string, pyFiles: string[]): string[] {
  const imports = new Set<string>()

  // Comprehensive Python stdlib set (3.10+)
  const stdlib = new Set([
    'abc', 'aifc', 'argparse', 'array', 'ast', 'asyncio', 'atexit',
    'base64', 'binascii', 'bisect', 'builtins', 'bz2',
    'calendar', 'cgi', 'cgitb', 'chunk', 'cmath', 'cmd', 'code', 'codecs',
    'codeop', 'collections', 'colorsys', 'compileall', 'concurrent',
    'configparser', 'contextlib', 'contextvars', 'copy', 'copyreg',
    'cProfile', 'csv', 'ctypes', 'curses',
    'dataclasses', 'datetime', 'dbm', 'decimal', 'difflib', 'dis',
    'distutils', 'doctest',
    'email', 'encodings', 'enum', 'errno',
    'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch',
    'formatter', 'fractions', 'ftplib', 'functools',
    'gc', 'getopt', 'getpass', 'gettext', 'glob', 'graphlib', 'grp', 'gzip',
    'hashlib', 'heapq', 'hmac', 'html', 'http',
    'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib', 'inspect', 'io',
    'ipaddress', 'itertools',
    'json',
    'keyword',
    'lib2to3', 'linecache', 'locale', 'logging', 'lzma',
    'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes', 'mmap',
    'modulefinder', 'multiprocessing', 'msvcrt',
    'netrc', 'nis', 'nntplib', 'numbers',
    'operator', 'optparse', 'os', 'ossaudiodev',
    'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
    'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint',
    'profile', 'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr',
    'pydoc',
    'queue', 'quopri',
    'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter',
    'runpy',
    'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex',
    'shutil', 'signal', 'site', 'smtpd', 'smtplib', 'sndhdr',
    'socket', 'socketserver', 'sqlite3', 'ssl', 'stat', 'statistics',
    'string', 'stringprep', 'struct', 'subprocess', 'sunau', 'symtable',
    'sys', 'sysconfig', 'syslog',
    'tabnanny', 'tarfile', 'telnetlib', 'tempfile', 'termios', 'test',
    'textwrap', 'threading', 'time', 'timeit', 'tkinter', 'token',
    'tokenize', 'tomllib', 'trace', 'traceback', 'tracemalloc', 'tty',
    'turtle', 'turtledemo', 'types', 'typing',
    'unicodedata', 'unittest', 'urllib', 'uu', 'uuid',
    'venv',
    'warnings', 'wave', 'weakref', 'webbrowser', 'winreg', 'winsound',
    'wsgiref',
    'xdrlib', 'xml', 'xmlrpc',
    'zipapp', 'zipfile', 'zipimport', 'zlib',
    '_thread', '__future__'
  ])

  // Also skip relative imports (starting with .)
  for (const file of pyFiles) {
    try {
      const content = readFileSync(join(dir, file), 'utf-8')
      for (const line of content.split('\n')) {
        const trimmed = line.trim()
        if (trimmed.startsWith('#')) continue

        // import foo / import foo.bar / import foo as f
        const importMatch = trimmed.match(/^import\s+([a-zA-Z_][a-zA-Z0-9_]*)/)
        if (importMatch && !stdlib.has(importMatch[1])) {
          imports.add(importMatch[1])
        }

        // from foo import bar / from foo.bar import baz
        const fromMatch = trimmed.match(/^from\s+([a-zA-Z_][a-zA-Z0-9_]*)/)
        if (fromMatch && !stdlib.has(fromMatch[1])) {
          imports.add(fromMatch[1])
        }
      }
    } catch { /* skip unreadable files */ }
  }

  return Array.from(imports)
}

/**
 * Extract third-party import/require names from JS/TS files.
 * Filters out Node.js built-in modules and relative imports.
 */
function extractJsImports(dir: string, jsFiles: string[]): string[] {
  const imports = new Set<string>()
  const builtins = new Set([
    'assert', 'buffer', 'child_process', 'cluster', 'console', 'constants',
    'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'http2',
    'https', 'inspector', 'module', 'net', 'os', 'path', 'perf_hooks',
    'process', 'punycode', 'querystring', 'readline', 'repl', 'stream',
    'string_decoder', 'sys', 'timers', 'tls', 'tty', 'url', 'util', 'v8',
    'vm', 'wasi', 'worker_threads', 'zlib'
  ])

  for (const file of jsFiles) {
    try {
      const content = readFileSync(join(dir, file), 'utf-8')
      for (const line of content.split('\n')) {
        const trimmed = line.trim()

        // import ... from 'package'
        const esmMatch = trimmed.match(/from\s+['"]([^./][^'"]*?)['"]/)
        if (esmMatch) {
          const pkgName = esmMatch[1].startsWith('@')
            ? esmMatch[1].split('/').slice(0, 2).join('/')
            : esmMatch[1].split('/')[0]
          if (!builtins.has(pkgName)) imports.add(pkgName)
        }

        // require('package')
        const cjsMatch = trimmed.match(/require\s*\(\s*['"]([^./][^'"]*?)['"]\s*\)/)
        if (cjsMatch) {
          const pkgName = cjsMatch[1].startsWith('@')
            ? cjsMatch[1].split('/').slice(0, 2).join('/')
            : cjsMatch[1].split('/')[0]
          if (!builtins.has(pkgName)) imports.add(pkgName)
        }
      }
    } catch { /* skip */ }
  }

  return Array.from(imports)
}

function shouldSkipDir(name: string): boolean {
  const skip = [
    'node_modules', '.git', 'dist', 'out', 'build', '.next', '.nuxt',
    '__pycache__', '.venv', 'venv', 'env', '.tox', 'target',
    'vendor', '.idea', '.vscode', '.cache', 'coverage', '.turbo',
    '.output', 'tmp', '.tmp', '.expo'
  ]
  return name.startsWith('.') || skip.includes(name)
}

function isMonorepoDir(name: string): boolean {
  return ['packages', 'apps', 'services', 'modules', 'libs', 'projects', 'crates', 'cmd', 'internal', 'api'].includes(name)
}

/**
 * Parse a directory as a service. Reads manifest files to extract packages.
 */
function parseServiceFromDir(dir: string, projectRoot: string): DiscoveredService | null {
  const relPath = relative(projectRoot, dir) || '.'
  const name = relPath === '.' ? basename(projectRoot) : relPath.replace(/\//g, '-')
  const id = slugify(name)

  const service: DiscoveredService = {
    id,
    name,
    path: relPath,
    ecosystem: 'npm',
    packages: [],
    techStack: [],
    hasDockerfile: existsSync(join(dir, 'Dockerfile')),
    envVars: parseEnvFile(dir)
  }

  // Try each ecosystem in order
  if (tryParseNodePackages(dir, service)) return service
  if (tryParseGoPackages(dir, service)) return service
  if (tryParsePythonPackages(dir, service)) return service
  if (tryParseRustPackages(dir, service)) return service
  if (tryParseJavaPackages(dir, service)) return service
  if (tryParseRubyPackages(dir, service)) return service

  return service.packages.length > 0 ? service : null
}

// ─── Ecosystem Parsers ────────────────────────────────────────

function tryParseNodePackages(dir: string, service: DiscoveredService): boolean {
  const pkgPath = join(dir, 'package.json')
  if (!existsSync(pkgPath)) return false

  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))
    service.ecosystem = 'npm'
    service.name = pkg.name || service.name

    const deps = pkg.dependencies ?? {}
    const devDeps = pkg.devDependencies ?? {}

    for (const [name, versionSpec] of Object.entries(deps)) {
      const version = cleanVersion(versionSpec as string)
      if (version) {
        service.packages.push({ name, version, ecosystem: 'npm', isDev: false })
        service.techStack.push(`${name}@${version}`)
      }
    }

    for (const [name, versionSpec] of Object.entries(devDeps)) {
      const version = cleanVersion(versionSpec as string)
      if (version) {
        service.packages.push({ name, version, ecosystem: 'npm', isDev: true })
      }
    }

    // Try to get exact versions from lock file
    enrichFromLockFile(dir, service)

    // Add runtime to tech stack
    if (pkg.engines?.node) {
      service.techStack.unshift(`Node.js ${cleanVersion(pkg.engines.node)}`)
    }

    return true
  } catch {
    return false
  }
}

function enrichFromLockFile(dir: string, service: DiscoveredService): void {
  // Try package-lock.json for exact versions
  const lockPath = join(dir, 'package-lock.json')
  if (!existsSync(lockPath)) return

  try {
    const lock = JSON.parse(readFileSync(lockPath, 'utf-8'))
    const lockPackages = lock.packages ?? lock.dependencies ?? {}

    for (const pkg of service.packages) {
      // package-lock v3 format: packages["node_modules/express"]
      const lockEntry = lockPackages[`node_modules/${pkg.name}`] ?? lockPackages[pkg.name]
      if (lockEntry?.version) {
        pkg.version = lockEntry.version
      }
    }
  } catch { /* ignore lock parse errors */ }
}

function tryParseGoPackages(dir: string, service: DiscoveredService): boolean {
  const modPath = join(dir, 'go.mod')
  if (!existsSync(modPath)) return false

  try {
    const content = readFileSync(modPath, 'utf-8')
    service.ecosystem = 'Go'

    // Extract module name
    const moduleMatch = content.match(/^module\s+(.+)$/m)
    if (moduleMatch) {
      service.name = moduleMatch[1].trim()
    }

    // Extract Go version
    const goVersionMatch = content.match(/^go\s+([\d.]+)$/m)
    if (goVersionMatch) {
      service.techStack.push(`Go ${goVersionMatch[1]}`)
    }

    // Parse require block
    const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/g)
    if (requireBlock) {
      for (const block of requireBlock) {
        const lines = block.split('\n').slice(1, -1) // skip require( and )
        for (const line of lines) {
          const match = line.trim().match(/^(.+?)\s+(v[\d.]+.*)$/)
          if (match && !line.includes('//')) {
            const name = match[1].trim()
            const version = match[2].trim()
            service.packages.push({ name, version, ecosystem: 'Go', isDev: false })
            service.techStack.push(`${basename(name)}@${version}`)
          }
        }
      }
    }

    // Also parse single-line requires
    const singleRequires = content.matchAll(/^require\s+(\S+)\s+(v[\d.]+\S*)/gm)
    for (const match of singleRequires) {
      service.packages.push({
        name: match[1], version: match[2], ecosystem: 'Go', isDev: false
      })
    }

    return service.packages.length > 0
  } catch {
    return false
  }
}

function tryParsePythonPackages(dir: string, service: DiscoveredService): boolean {
  // Try requirements.txt
  const reqPath = join(dir, 'requirements.txt')
  if (existsSync(reqPath)) {
    try {
      const content = readFileSync(reqPath, 'utf-8')
      service.ecosystem = 'PyPI'
      service.techStack.push('Python')

      for (const line of content.split('\n')) {
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue

        const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*(?:==|>=|~=)\s*(.+)$/)
        if (match) {
          service.packages.push({
            name: match[1], version: match[2].split(',')[0].trim(),
            ecosystem: 'PyPI', isDev: false
          })
          service.techStack.push(`${match[1]}@${match[2].split(',')[0].trim()}`)
        } else {
          // Package without version
          const nameOnly = trimmed.match(/^([a-zA-Z0-9_.-]+)/)
          if (nameOnly) {
            service.packages.push({
              name: nameOnly[1], version: '0.0.0',
              ecosystem: 'PyPI', isDev: false
            })
          }
        }
      }
      return service.packages.length > 0
    } catch { /* fall through */ }
  }

  // Try pyproject.toml (basic parsing, no TOML lib needed)
  const pyprojectPath = join(dir, 'pyproject.toml')
  if (existsSync(pyprojectPath)) {
    try {
      const content = readFileSync(pyprojectPath, 'utf-8')
      service.ecosystem = 'PyPI'
      service.techStack.push('Python')

      // Extract dependencies from pyproject.toml
      const depSection = content.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/m)
      if (depSection) {
        const depLines = depSection[1].split('\n')
        for (const line of depLines) {
          const match = line.match(/"([a-zA-Z0-9_.-]+)\s*(?:>=|==|~=)\s*([\d.]+)/)
          if (match) {
            service.packages.push({
              name: match[1], version: match[2],
              ecosystem: 'PyPI', isDev: false
            })
          }
        }
      }
      return service.packages.length > 0
    } catch { /* fall through */ }
  }

  // Try Pipfile (basic parsing)
  const pipfilePath = join(dir, 'Pipfile')
  if (existsSync(pipfilePath)) {
    try {
      const content = readFileSync(pipfilePath, 'utf-8')
      service.ecosystem = 'PyPI'
      service.techStack.push('Python')

      const pkgSection = content.match(/\[packages\]([\s\S]*?)(?:\[|$)/m)
      if (pkgSection) {
        const lines = pkgSection[1].split('\n')
        for (const line of lines) {
          const match = line.match(/^([a-zA-Z0-9_.-]+)\s*=\s*"(?:==)?([\d.]+)"/)
          if (match) {
            service.packages.push({
              name: match[1], version: match[2],
              ecosystem: 'PyPI', isDev: false
            })
          }
        }
      }
      return service.packages.length > 0
    } catch { /* fall through */ }
  }

  return false
}

function tryParseRustPackages(dir: string, service: DiscoveredService): boolean {
  const cargoPath = join(dir, 'Cargo.toml')
  if (!existsSync(cargoPath)) return false

  try {
    const content = readFileSync(cargoPath, 'utf-8')
    service.ecosystem = 'crates.io'

    // Extract package name
    const nameMatch = content.match(/^\[package\][\s\S]*?name\s*=\s*"(.+?)"/m)
    if (nameMatch) service.name = nameMatch[1]

    service.techStack.push('Rust')

    // Parse [dependencies] section
    const depSection = content.match(/\[dependencies\]([\s\S]*?)(?:\[|$)/)
    if (depSection) {
      for (const line of depSection[1].split('\n')) {
        // Simple: name = "version"
        const simple = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([\d.]+.*?)"/)
        if (simple) {
          service.packages.push({
            name: simple[1], version: simple[2],
            ecosystem: 'crates.io', isDev: false
          })
          continue
        }
        // Complex: name = { version = "..." }
        const complex = line.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*?version\s*=\s*"([\d.]+.*?)"/)
        if (complex) {
          service.packages.push({
            name: complex[1], version: complex[2],
            ecosystem: 'crates.io', isDev: false
          })
        }
      }
    }

    // Also check Cargo.lock for exact versions
    const lockPath = join(dir, 'Cargo.lock')
    if (existsSync(lockPath)) {
      try {
        const lockContent = readFileSync(lockPath, 'utf-8')
        for (const pkg of service.packages) {
          const lockMatch = lockContent.match(
            new RegExp(`\\[\\[package\\]\\]\\s*name\\s*=\\s*"${pkg.name}"\\s*version\\s*=\\s*"([^"]+)"`)
          )
          if (lockMatch) {
            pkg.version = lockMatch[1]
          }
        }
      } catch { /* ignore */ }
    }

    return service.packages.length > 0
  } catch {
    return false
  }
}

function tryParseJavaPackages(dir: string, service: DiscoveredService): boolean {
  const pomPath = join(dir, 'pom.xml')
  if (!existsSync(pomPath)) return false

  try {
    const content = readFileSync(pomPath, 'utf-8')
    service.ecosystem = 'Maven'
    service.techStack.push('Java')

    // Extract artifactId as service name
    const artifactMatch = content.match(/<artifactId>(.+?)<\/artifactId>/)
    if (artifactMatch) service.name = artifactMatch[1]

    // Parse dependencies
    const depMatches = content.matchAll(
      /<dependency>\s*<groupId>(.+?)<\/groupId>\s*<artifactId>(.+?)<\/artifactId>\s*(?:<version>(.+?)<\/version>)?/gs
    )

    for (const match of depMatches) {
      const groupId = match[1]
      const artifactId = match[2]
      const version = match[3] ?? '0.0.0'
      service.packages.push({
        name: `${groupId}:${artifactId}`,
        version,
        ecosystem: 'Maven',
        isDev: false
      })
      service.techStack.push(`${artifactId}@${version}`)
    }

    return service.packages.length > 0
  } catch {
    return false
  }
}

function tryParseRubyPackages(dir: string, service: DiscoveredService): boolean {
  const gemfilePath = join(dir, 'Gemfile')
  if (!existsSync(gemfilePath)) return false

  try {
    const content = readFileSync(gemfilePath, 'utf-8')
    service.ecosystem = 'RubyGems'
    service.techStack.push('Ruby')

    for (const line of content.split('\n')) {
      const match = line.match(/gem\s+['"]([^'"]+)['"](?:\s*,\s*['"](?:~>|>=|=)?\s*([\d.]+)['"])?/)
      if (match) {
        service.packages.push({
          name: match[1], version: match[2] ?? '0.0.0',
          ecosystem: 'RubyGems', isDev: false
        })
      }
    }

    // Enrich from Gemfile.lock
    const lockPath = join(dir, 'Gemfile.lock')
    if (existsSync(lockPath)) {
      try {
        const lockContent = readFileSync(lockPath, 'utf-8')
        for (const pkg of service.packages) {
          const lockMatch = lockContent.match(new RegExp(`^\\s+${pkg.name}\\s+\\((\\d[\\d.]*)\\)`, 'm'))
          if (lockMatch) {
            pkg.version = lockMatch[1]
          }
        }
      } catch { /* ignore */ }
    }

    return service.packages.length > 0
  } catch {
    return false
  }
}

// ─── Phase 2: Dependency Discovery ────────────────────────────

/**
 * Infer inter-service dependencies from:
 * - docker-compose.yml (depends_on, links)
 * - Environment variables referencing other services
 * - Shared package imports (monorepo)
 */
function discoverDependencies(projectDir: string, services: DiscoveredService[]): Dependency[] {
  const deps: Dependency[] = []
  const serviceIds = new Set(services.map(s => s.id))

  // 1. Parse docker-compose if it exists
  deps.push(...parseDockerComposeDeps(projectDir, services))

  // 2. Infer from environment variables
  deps.push(...inferDepsFromEnvVars(services))

  // 3. Infer database dependencies (services referencing DB packages)
  deps.push(...inferDatabaseDeps(services))

  // 4. Infer auth dependencies (services using auth/jwt packages)
  deps.push(...inferAuthDeps(services))

  // Deduplicate
  const seen = new Set<string>()
  return deps.filter(d => {
    // Only keep deps between known services
    if (!serviceIds.has(d.from) || !serviceIds.has(d.to)) return false
    if (d.from === d.to) return false
    const key = `${d.from}->${d.to}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

/**
 * Parse docker-compose.yml for depends_on and links.
 * Uses regex-based parsing to avoid needing a YAML library.
 */
function parseDockerComposeDeps(projectDir: string, services: DiscoveredService[]): Dependency[] {
  const deps: Dependency[] = []
  const composeFiles = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']

  for (const file of composeFiles) {
    const composePath = join(projectDir, file)
    if (!existsSync(composePath)) continue

    try {
      const content = readFileSync(composePath, 'utf-8')
      const serviceBlocks = content.split(/^\s{2}\w/m)

      // Extract service names and their depends_on
      const composeServices = new Map<string, string[]>()

      // Simple regex-based YAML parsing for depends_on
      const serviceNameRegex = /^\s{2}(\w[\w-]*):/gm
      const serviceNames: string[] = []
      let match: RegExpExecArray | null

      while ((match = serviceNameRegex.exec(content)) !== null) {
        serviceNames.push(match[1])
      }

      for (const svcName of serviceNames) {
        // Find depends_on block after this service
        const svcRegex = new RegExp(
          `^\\s{2}${svcName}:[\\s\\S]*?depends_on:\\s*\\n((?:\\s+-\\s+\\w[\\w-]*\\n?)+)`,
          'm'
        )
        const svcMatch = svcRegex.exec(content)
        if (svcMatch) {
          const depNames = [...svcMatch[1].matchAll(/^\s+-\s+(\w[\w-]*)/gm)].map(m => m[1])
          composeServices.set(svcName, depNames)
        }
      }

      // Map compose service names to discovered service IDs
      const nameToId = buildNameToIdMap(services)

      for (const [from, tos] of composeServices) {
        const fromId = nameToId.get(from)
        if (!fromId) continue
        for (const to of tos) {
          const toId = nameToId.get(to)
          if (!toId) continue
          deps.push({
            from: fromId,
            to: toId,
            type: 'api',
            propagationWeight: 0.7,
            description: `${from} depends_on ${to} (docker-compose)`
          })
        }
      }
    } catch { /* ignore parse errors */ }
  }

  return deps
}

/**
 * Infer dependencies from environment variables that reference other services.
 */
function inferDepsFromEnvVars(services: DiscoveredService[]): Dependency[] {
  const deps: Dependency[] = []

  for (const service of services) {
    for (const [key, value] of Object.entries(service.envVars)) {
      const keyUpper = key.toUpperCase()

      // Look for DATABASE_URL, DB_HOST, POSTGRES_HOST, MYSQL_HOST, etc.
      if (keyUpper.includes('DATABASE') || keyUpper.includes('DB_HOST') ||
          keyUpper.includes('POSTGRES') || keyUpper.includes('MYSQL') ||
          keyUpper.includes('MONGO') || keyUpper.includes('REDIS')) {

        // Find a DB service
        const dbService = services.find(s =>
          s.id !== service.id && (
            s.packages.some(p =>
              p.name.includes('postgres') || p.name.includes('mysql') ||
              p.name.includes('mongo') || p.name.includes('redis') ||
              p.name.includes('pg') || p.name.includes('sqlite')
            ) ||
            s.name.toLowerCase().includes('database') ||
            s.name.toLowerCase().includes('db')
          )
        )
        if (dbService) {
          deps.push({
            from: service.id,
            to: dbService.id,
            type: 'data',
            propagationWeight: 0.8,
            description: `${service.name} connects to ${dbService.name} via ${key}`
          })
        }
      }

      // Look for AUTH_URL, AUTH_SERVICE, etc.
      if (keyUpper.includes('AUTH') || keyUpper.includes('OAUTH') || keyUpper.includes('JWT')) {
        const authService = services.find(s =>
          s.id !== service.id && (
            s.name.toLowerCase().includes('auth') ||
            s.packages.some(p =>
              p.name.includes('passport') || p.name.includes('oauth') ||
              p.name.includes('jwt') || p.name.includes('auth')
            )
          )
        )
        if (authService) {
          deps.push({
            from: service.id,
            to: authService.id,
            type: 'auth',
            propagationWeight: 0.8,
            description: `${service.name} authenticates via ${authService.name}`
          })
        }
      }

      // Look for _URL or _HOST vars referencing other service names
      if (keyUpper.endsWith('_URL') || keyUpper.endsWith('_HOST') || keyUpper.endsWith('_SERVICE')) {
        for (const other of services) {
          if (other.id === service.id) continue
          const otherSlug = other.name.toLowerCase().replace(/[^a-z0-9]/g, '')
          if (keyUpper.toLowerCase().includes(otherSlug) || value.toLowerCase().includes(otherSlug)) {
            deps.push({
              from: service.id,
              to: other.id,
              type: 'api',
              propagationWeight: 0.6,
              description: `${service.name} references ${other.name} in env var ${key}`
            })
          }
        }
      }
    }
  }

  return deps
}

/**
 * Infer database dependencies from DB client packages.
 */
function inferDatabaseDeps(services: DiscoveredService[]): Dependency[] {
  const deps: Dependency[] = []

  const dbClientPackages = [
    'pg', 'postgres', 'mysql2', 'mysql', 'mongodb', 'mongoose', 'redis', 'ioredis',
    'prisma', '@prisma/client', 'sequelize', 'typeorm', 'knex', 'drizzle-orm',
    'psycopg2', 'asyncpg', 'sqlalchemy', 'django', 'pymongo', 'redis-py',
    'database/sql', 'gorm.io/gorm', 'jackc/pgx', 'go-redis/redis',
    'diesel', 'sqlx', 'sea-orm',
    'jdbc', 'hibernate'
  ]

  // Find the "most database-like" service (or any service with DB packages)
  const dbServices = services.filter(s =>
    s.name.toLowerCase().includes('database') ||
    s.name.toLowerCase().includes('db') ||
    s.packages.some(p =>
      p.name.includes('postgresql') || p.name.includes('mysql-server') ||
      p.name.includes('mongodb-') || p.name.includes('redis-server')
    )
  )

  for (const service of services) {
    if (dbServices.some(db => db.id === service.id)) continue

    const usesDbClient = service.packages.some(p =>
      dbClientPackages.some(dbPkg => p.name.includes(dbPkg))
    )

    if (usesDbClient) {
      for (const db of dbServices) {
        deps.push({
          from: service.id,
          to: db.id,
          type: 'data',
          propagationWeight: 0.85,
          description: `${service.name} uses database client packages`
        })
      }
    }
  }

  return deps
}

/**
 * Infer auth dependencies from auth-related packages.
 */
function inferAuthDeps(services: DiscoveredService[]): Dependency[] {
  const deps: Dependency[] = []

  const authPackages = [
    'passport', 'jsonwebtoken', 'jose', 'next-auth', '@auth/core',
    'bcrypt', 'argon2', 'oauth', 'openid-client',
    'flask-login', 'django-allauth', 'python-jose', 'pyjwt',
    'golang-jwt', 'oauth2', 'casbin'
  ]

  const authServices = services.filter(s =>
    s.name.toLowerCase().includes('auth') ||
    s.name.toLowerCase().includes('identity') ||
    s.name.toLowerCase().includes('sso')
  )

  if (authServices.length === 0) return deps

  for (const service of services) {
    if (authServices.some(a => a.id === service.id)) continue

    const usesAuthPkg = service.packages.some(p =>
      authPackages.some(authPkg => p.name.includes(authPkg))
    )

    if (usesAuthPkg) {
      for (const auth of authServices) {
        deps.push({
          from: service.id,
          to: auth.id,
          type: 'auth',
          propagationWeight: 0.75,
          description: `${service.name} uses auth-related packages`
        })
      }
    }
  }

  return deps
}

// ─── Phase 3: Vulnerability Discovery (OSV.dev) ──────────────

/**
 * Query OSV.dev for each package across all services.
 * Uses individual queries (the batch endpoint returns truncated results).
 * Runs queries concurrently in groups to balance speed and rate limits.
 */
async function discoverVulnerabilities(
  services: DiscoveredService[],
  onProgress?: (pct: number, msg: string) => void
): Promise<Vulnerability[]> {
  // Collect unique packages across all services
  const packageMap = new Map<string, { pkg: DiscoveredPackage; serviceIds: string[] }>()

  for (const service of services) {
    for (const pkg of service.packages) {
      if (pkg.isDev) continue
      if (pkg.version === '0.0.0') continue // skip packages without versions

      const key = `${pkg.ecosystem}:${pkg.name}@${pkg.version}`
      const existing = packageMap.get(key)
      if (existing) {
        existing.serviceIds.push(service.id)
      } else {
        packageMap.set(key, { pkg, serviceIds: [service.id] })
      }
    }
  }

  const entries = Array.from(packageMap.values())
  if (entries.length === 0) return []

  const allVulns: Vulnerability[] = []
  const seenCves = new Set<string>()
  let vulnCounter = 0

  // Run queries concurrently in groups of 10
  const concurrency = 10
  const batches: typeof entries[] = []
  for (let i = 0; i < entries.length; i += concurrency) {
    batches.push(entries.slice(i, i + concurrency))
  }

  let completed = 0
  for (const batch of batches) {
    const promises = batch.map(async ({ pkg, serviceIds }) => {
      try {
        const osvVulns = await osvQuery(pkg.name, pkg.ecosystem, pkg.version)
        return { osvVulns, pkg, serviceIds }
      } catch {
        return { osvVulns: [] as OsvVuln[], pkg, serviceIds }
      }
    })

    const results = await Promise.all(promises)
    completed += batch.length

    const pct = Math.round((completed / entries.length) * 90)
    onProgress?.(pct, `Queried ${completed}/${entries.length} packages (${allVulns.length} vulns found)...`)

    for (const { osvVulns, pkg, serviceIds } of results) {
      for (const osvVuln of osvVulns) {
        const cveId = osvVuln.aliases?.find((a: string) => a.startsWith('CVE-')) ?? osvVuln.id

        if (seenCves.has(cveId)) {
          const existing = allVulns.find(v => v.cveId === cveId)
          if (existing) {
            for (const sid of serviceIds) {
              if (!existing.affectedServiceIds.includes(sid)) {
                existing.affectedServiceIds.push(sid)
              }
            }
          }
          continue
        }
        seenCves.add(cveId)

        vulnCounter++
        const vuln = osvToVulnerability(osvVuln, vulnCounter, pkg, serviceIds)
        allVulns.push(vuln)
      }
    }
  }

  return allVulns
}

/**
 * Query OSV.dev for vulnerabilities affecting a specific package+version.
 * Uses POST /v1/query which returns full vulnerability details.
 */
function osvQuery(packageName: string, ecosystem: string, version: string): Promise<OsvVuln[]> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      package: { name: packageName, ecosystem },
      version
    })

    const request = net.request({
      method: 'POST',
      url: 'https://api.osv.dev/v1/query'
    })

    request.setHeader('Content-Type', 'application/json')

    let responseBody = ''
    request.on('response', (response) => {
      response.on('data', (chunk) => { responseBody += chunk.toString() })
      response.on('end', () => {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          try {
            const data = JSON.parse(responseBody)
            resolve(data.vulns ?? [])
          } catch {
            resolve([])
          }
        } else {
          resolve([]) // Don't fail the whole scan for one package
        }
      })
    })

    request.on('error', () => resolve([])) // Graceful fallback
    request.write(body)
    request.end()
  })
}

/**
 * Convert an OSV vulnerability to the FAVR engine Vulnerability type.
 */
function osvToVulnerability(
  osv: OsvVuln,
  index: number,
  pkg: DiscoveredPackage,
  serviceIds: string[]
): Vulnerability {
  const cveId = osv.aliases?.find(a => a.startsWith('CVE-')) ?? osv.id
  const cvss = extractCvssScore(osv)
  const severity = cvssToSeverity(cvss)

  // Find the fixed version from affected ranges
  let patchedVersion = 'unknown'
  if (osv.affected) {
    for (const affected of osv.affected) {
      if (affected.ranges) {
        for (const range of affected.ranges) {
          const fixedEvent = range.events?.find(e => e.fixed)
          if (fixedEvent?.fixed) {
            patchedVersion = `${pkg.name}@${fixedEvent.fixed}`
            break
          }
        }
      }
      if (patchedVersion !== 'unknown') break
    }
  }

  // Check for known exploit references
  const knownExploit = osv.references?.some(r =>
    r.type === 'EVIDENCE' ||
    r.url?.includes('exploit') ||
    r.url?.includes('poc') ||
    r.url?.includes('metasploit')
  ) ?? false

  return {
    id: `vuln-${String(index).padStart(3, '0')}`,
    cveId,
    title: osv.summary || `${cveId} in ${pkg.name}`,
    description: osv.details?.slice(0, 500) || osv.summary || '',
    severity,
    cvssScore: cvss,
    epssScore: 0, // Will be enriched by the engine's EPSS phase
    exploitProbability: estimateExploitProb(cvss, knownExploit),
    affectedServiceIds: [...serviceIds],
    affectedPackage: `${pkg.name}@${pkg.version}`,
    patchedVersion,
    remediationCost: estimateRemediationCost(severity),
    remediationDowntime: estimateDowntime(severity),
    complexity: cvss >= 8 ? 'high' : cvss >= 5 ? 'medium' : 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit,
    complianceViolations: [],
    complianceDeadlineDays: null
  }
}

/**
 * Extract a numeric CVSS score from OSV severity data.
 */
function extractCvssScore(osv: OsvVuln): number {
  if (osv.severity && osv.severity.length > 0) {
    for (const sev of osv.severity) {
      if (sev.type === 'CVSS_V3' && sev.score) {
        // Score can be a CVSS vector string — extract base score
        const numericScore = parseCvssVector(sev.score)
        if (numericScore > 0) return numericScore
      }
    }
  }

  // Check database_specific for severity string
  const dbSeverity = osv.database_specific?.severity
  if (typeof dbSeverity === 'string') {
    switch (dbSeverity.toUpperCase()) {
      case 'CRITICAL': return 9.5
      case 'HIGH': return 7.5
      case 'MODERATE':
      case 'MEDIUM': return 5.5
      case 'LOW': return 3.0
    }
  }

  return 5.0 // default
}

/**
 * Parse CVSS v3 vector string to approximate a base score.
 * Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
 */
function parseCvssVector(vector: string): number {
  if (!vector.startsWith('CVSS:')) return 0

  const metrics: Record<string, string> = {}
  const parts = vector.split('/')
  for (const part of parts) {
    const [key, val] = part.split(':')
    if (key && val) metrics[key] = val
  }

  // Simplified CVSS v3 calculation
  const avScores: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
  const acScores: Record<string, number> = { L: 0.77, H: 0.44 }
  const prScoresUnchanged: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 }
  const prScoresChanged: Record<string, number> = { N: 0.85, L: 0.68, H: 0.50 }
  const uiScores: Record<string, number> = { N: 0.85, R: 0.62 }
  const impactScores: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }

  const scopeChanged = metrics['S'] === 'C'

  const av = avScores[metrics['AV']] ?? 0.85
  const ac = acScores[metrics['AC']] ?? 0.77
  const pr = scopeChanged
    ? (prScoresChanged[metrics['PR']] ?? 0.85)
    : (prScoresUnchanged[metrics['PR']] ?? 0.85)
  const ui = uiScores[metrics['UI']] ?? 0.85

  const exploitability = 8.22 * av * ac * pr * ui

  const confImpact = impactScores[metrics['C']] ?? 0
  const intImpact = impactScores[metrics['I']] ?? 0
  const availImpact = impactScores[metrics['A']] ?? 0

  const iss = 1 - ((1 - confImpact) * (1 - intImpact) * (1 - availImpact))

  let impact: number
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
  } else {
    impact = 6.42 * iss
  }

  if (impact <= 0) return 0

  let baseScore: number
  if (scopeChanged) {
    baseScore = Math.min(1.08 * (impact + exploitability), 10)
  } else {
    baseScore = Math.min(impact + exploitability, 10)
  }

  return Math.round(baseScore * 10) / 10
}

// ─── Helper Functions ─────────────────────────────────────────

function toEngineService(d: DiscoveredService): Service {
  const tier = inferTier(d)
  return {
    id: d.id,
    name: d.name,
    techStack: d.techStack.slice(0, 15), // cap at 15 entries
    tier,
    sla: tier === 'critical' ? 99.99 : tier === 'high' ? 99.9 : tier === 'medium' ? 99.5 : 99.0,
    description: `Auto-discovered ${d.ecosystem} service at ${d.path}`,
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: [],
    maintenanceWindow: defaultMaintenanceWindow(tier)
  }
}

function inferTier(service: DiscoveredService): 'critical' | 'high' | 'medium' | 'low' {
  const name = service.name.toLowerCase()

  // Critical: payment, auth, database, gateway, core
  if (/\b(payment|billing|auth|identity|sso|database|db|gateway|core)\b/.test(name)) {
    return 'critical'
  }

  // High: API, backend, server, main app
  if (/\b(api|backend|server|web|app|main|service)\b/.test(name)) {
    return 'high'
  }

  // Low: dev tools, test, docs
  if (/\b(test|docs|tool|script|dev|mock|stub|fixture)\b/.test(name)) {
    return 'low'
  }

  return 'medium'
}

function defaultMaintenanceWindow(tier: string): MaintenanceWindow {
  if (tier === 'critical') {
    return { day: 'Saturday', startTime: '02:00', endTime: '06:00', timezone: 'UTC', durationMinutes: 240 }
  }
  if (tier === 'high') {
    return { day: 'Sunday', startTime: '00:00', endTime: '06:00', timezone: 'UTC', durationMinutes: 360 }
  }
  return { day: 'Wednesday', startTime: '22:00', endTime: '02:00', timezone: 'UTC', durationMinutes: 240 }
}

function buildNameToIdMap(services: DiscoveredService[]): Map<string, string> {
  const map = new Map<string, string>()
  for (const s of services) {
    map.set(s.name.toLowerCase(), s.id)
    map.set(s.id, s.id)
    // Also map the last path segment
    const lastSegment = s.path.split('/').pop()?.toLowerCase()
    if (lastSegment) map.set(lastSegment, s.id)
  }
  return map
}

function parseEnvFile(dir: string): Record<string, string> {
  const envVars: Record<string, string> = {}
  const envFiles = ['.env', '.env.local', '.env.production', '.env.example']

  for (const file of envFiles) {
    const envPath = join(dir, file)
    if (!existsSync(envPath)) continue

    try {
      const content = readFileSync(envPath, 'utf-8')
      for (const line of content.split('\n')) {
        const trimmed = line.trim()
        if (!trimmed || trimmed.startsWith('#')) continue
        const eqIdx = trimmed.indexOf('=')
        if (eqIdx > 0) {
          const key = trimmed.slice(0, eqIdx).trim()
          const value = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '')
          envVars[key] = value
        }
      }
    } catch { /* ignore */ }
  }

  return envVars
}

function cleanVersion(spec: string): string {
  // Remove semver prefixes: ^, ~, >=, <=, =, >
  return spec.replace(/^[\^~>=<]+\s*/, '').split(' ')[0]
}

function slugify(str: string): string {
  return str
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    || 'service'
}

function cvssToSeverity(cvss: number): Severity {
  if (cvss >= 9) return 'critical'
  if (cvss >= 7) return 'high'
  if (cvss >= 4) return 'medium'
  return 'low'
}

function estimateExploitProb(cvss: number, knownExploit: boolean): number {
  const base = 1 / (1 + Math.exp(-0.6 * (cvss - 6)))
  return knownExploit ? Math.min(0.95, base * 2) : base
}

function estimateRemediationCost(severity: Severity): number {
  switch (severity) {
    case 'critical': return 4
    case 'high': return 3
    case 'medium': return 2
    case 'low': return 1
  }
}

function estimateDowntime(severity: Severity): number {
  switch (severity) {
    case 'critical': return 30
    case 'high': return 15
    case 'medium': return 10
    case 'low': return 5
  }
}
