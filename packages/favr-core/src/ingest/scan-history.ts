/**
 * Scan History Store — persists scan results for re-opening and incremental scanning.
 *
 * Stores scan metadata + full analysis JSON locally using a plain JSON file.
 * No Electron dependencies — works in CLI and desktop environments.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { homedir } from 'os'
import type { ScanSnapshot } from './codebase-analyzer.js'

// ─── Types ───────────────────────────────────────────────────

export interface ScanHistoryEntry {
  id: string
  projectPath: string
  projectName: string
  timestamp: number
  durationMs: number
  stats: {
    servicesFound: number
    packagesScanned: number
    vulnerabilitiesFound: number
    ecosystems: string[]
    unresolvedPackages: number
    dockerImagesScanned: number
    isMonorepo: boolean
    scanDurationMs: number
  }
  /** Full serialized analysis result */
  analysisJson: string
  /** Snapshot for incremental scanning */
  snapshot: ScanSnapshot
}

interface ScanHistorySchema {
  scans: ScanHistoryEntry[]
}

// ─── File-based Store ────────────────────────────────────────

let _storePath: string | null = null

function getStorePath(): string {
  if (_storePath) return _storePath
  const dir = join(homedir(), '.favr')
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  return join(dir, 'scan-history.json')
}

/** Override the default store path (e.g. for testing or project-local history). */
export function setStorePath(path: string): void {
  const dir = dirname(path)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  _storePath = path
}

function readStore(): ScanHistorySchema {
  const path = getStorePath()
  if (!existsSync(path)) return { scans: [] }
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return { scans: [] }
  }
}

function writeStore(data: ScanHistorySchema): void {
  writeFileSync(getStorePath(), JSON.stringify(data, null, 2))
}

const MAX_HISTORY_ENTRIES = 100

// ─── Public API ──────────────────────────────────────────────

/**
 * Save a completed scan to history.
 */
export function saveScanResult(entry: Omit<ScanHistoryEntry, 'id'>): string {
  const id = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const store = readStore()

  store.scans.unshift({ ...entry, id })

  // Trim old entries
  if (store.scans.length > MAX_HISTORY_ENTRIES) {
    store.scans.length = MAX_HISTORY_ENTRIES
  }

  writeStore(store)
  return id
}

/**
 * Get all scan history entries (without full analysis JSON for performance).
 */
export function listScanHistory(): Array<Omit<ScanHistoryEntry, 'analysisJson' | 'snapshot'>> {
  const store = readStore()
  return store.scans.map(({ analysisJson, snapshot, ...rest }) => rest)
}

/**
 * Get scan history for a specific project path.
 */
export function getProjectHistory(projectPath: string): Array<Omit<ScanHistoryEntry, 'analysisJson' | 'snapshot'>> {
  const normalized = projectPath.replace(/\\/g, '/')
  return listScanHistory().filter(s => s.projectPath.replace(/\\/g, '/') === normalized)
}

/**
 * Load a full scan result by ID.
 */
export function loadScanResult(scanId: string): ScanHistoryEntry | null {
  const store = readStore()
  return store.scans.find(s => s.id === scanId) ?? null
}

/**
 * Get the most recent scan result for a project.
 */
export function getLatestScan(projectPath: string): ScanHistoryEntry | null {
  const normalized = projectPath.replace(/\\/g, '/')
  const store = readStore()
  return store.scans.find(s => s.projectPath.replace(/\\/g, '/') === normalized) ?? null
}

/**
 * Get the most recent scan snapshot for a project (for incremental scanning).
 */
export function getLatestSnapshot(projectPath: string): ScanSnapshot | null {
  const entry = getLatestScan(projectPath)
  return entry?.snapshot ?? null
}

/**
 * Delete a scan from history.
 */
export function deleteScanResult(scanId: string): boolean {
  const store = readStore()
  const idx = store.scans.findIndex(s => s.id === scanId)
  if (idx === -1) return false
  store.scans.splice(idx, 1)
  writeStore(store)
  return true
}

/**
 * Clear all scan history.
 */
export function clearScanHistory(): void {
  writeStore({ scans: [] })
}
