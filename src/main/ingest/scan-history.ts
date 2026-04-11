/**
 * Scan History Store — persists scan results for re-opening and incremental scanning.
 *
 * Stores scan metadata + full analysis JSON locally using electron-store.
 * Supports listing past scans, loading a previous result, and providing
 * snapshots for incremental re-scans.
 */

import Store from 'electron-store'
import type { ScanSnapshot } from './codebase-analyzer'

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

// ─── Store ───────────────────────────────────────────────────

const historyStore = new Store<ScanHistorySchema>({
  name: 'favr-scan-history',
  defaults: {
    scans: []
  }
})

const MAX_HISTORY_ENTRIES = 100

// ─── Public API ──────────────────────────────────────────────

/**
 * Save a completed scan to history.
 */
export function saveScanResult(entry: Omit<ScanHistoryEntry, 'id'>): string {
  const id = `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  const scans = historyStore.get('scans')

  scans.unshift({ ...entry, id })

  // Trim old entries
  if (scans.length > MAX_HISTORY_ENTRIES) {
    scans.length = MAX_HISTORY_ENTRIES
  }

  historyStore.set('scans', scans)
  return id
}

/**
 * Get all scan history entries (without full analysis JSON for performance).
 */
export function listScanHistory(): Array<Omit<ScanHistoryEntry, 'analysisJson' | 'snapshot'>> {
  const scans = historyStore.get('scans')
  return scans.map(({ analysisJson, snapshot, ...rest }) => rest)
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
  const scans = historyStore.get('scans')
  return scans.find(s => s.id === scanId) ?? null
}

/**
 * Get the most recent scan snapshot for a project (for incremental scanning).
 */
export function getLatestSnapshot(projectPath: string): ScanSnapshot | null {
  const normalized = projectPath.replace(/\\/g, '/')
  const scans = historyStore.get('scans')
  const match = scans.find(s => s.projectPath.replace(/\\/g, '/') === normalized)
  return match?.snapshot ?? null
}

/**
 * Delete a scan from history.
 */
export function deleteScanResult(scanId: string): boolean {
  const scans = historyStore.get('scans')
  const idx = scans.findIndex(s => s.id === scanId)
  if (idx === -1) return false
  scans.splice(idx, 1)
  historyStore.set('scans', scans)
  return true
}

/**
 * Clear all scan history.
 */
export function clearScanHistory(): void {
  historyStore.set('scans', [])
}
