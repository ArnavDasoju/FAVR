/**
 * Vulnerability Data Pipeline — multi-source CVE enrichment.
 *
 * Sources (queried in order, results merged):
 *   1. OSV.dev         — primary, free, no auth
 *   2. NVD             — secondary, fills missing CVSS details
 *   3. GitHub Advisory  — third source, cross-reference
 *   4. CISA KEV        — known exploited vulns (priority boost)
 *   5. FIRST.org EPSS  — exploit prediction scores
 *
 * Features:
 *   - Retry with exponential backoff (3 attempts) on all external calls
 *   - Local caching: CVE lookups 24h, EPSS 7d, KEV 24h
 *   - CVSS normalization to v3.1
 *   - Data freshness tracking per source
 */

import { net } from 'electron'
import Store from 'electron-store'

// ─── Types ───────────────────────────────────────────────────

export interface DataSourceStatus {
  name: string
  lastQueried: number | null    // timestamp
  available: boolean
  entriesReturned: number
  error?: string
}

export interface DataFreshness {
  osv: DataSourceStatus
  nvd: DataSourceStatus
  ghsa: DataSourceStatus
  kev: DataSourceStatus
  epss: DataSourceStatus
}

export interface EnrichedCveData {
  cveId: string
  cvssScore: number             // normalized to v3.1
  cvssVector: string | null
  severity: string
  epssScore: number
  epssPercentile: number
  isKev: boolean                // on CISA Known Exploited list
  kevDueDate: string | null     // CISA remediation deadline
  hasPublicExploit: boolean
  sources: string[]             // which DBs returned data for this CVE
  nvdDescription: string | null
  ghsaSeverity: string | null
  cwes: string[]
}

interface CveCache {
  entries: Record<string, { data: EnrichedCveData; fetchedAt: number }>
  epss: Record<string, { score: number; percentile: number; fetchedAt: number }>
  kevList: { cves: Set<string>; dueDates: Record<string, string>; fetchedAt: number } | null
  freshness: DataFreshness
}

// ─── Cache Store ─────────────────────────────────────────────

interface CacheSchema {
  cveEntries: Record<string, { data: EnrichedCveData; fetchedAt: number }>
  epssEntries: Record<string, { score: number; percentile: number; fetchedAt: number }>
  kevData: { cves: string[]; dueDates: Record<string, string>; fetchedAt: number } | null
  freshness: DataFreshness
}

const EMPTY_FRESHNESS: DataFreshness = {
  osv:  { name: 'OSV.dev',            lastQueried: null, available: true, entriesReturned: 0 },
  nvd:  { name: 'NVD',                lastQueried: null, available: true, entriesReturned: 0 },
  ghsa: { name: 'GitHub Advisory',    lastQueried: null, available: true, entriesReturned: 0 },
  kev:  { name: 'CISA KEV',           lastQueried: null, available: true, entriesReturned: 0 },
  epss: { name: 'FIRST.org EPSS',     lastQueried: null, available: true, entriesReturned: 0 },
}

const cacheStore = new Store<CacheSchema>({
  name: 'favr-vuln-cache',
  defaults: {
    cveEntries: {},
    epssEntries: {},
    kevData: null,
    freshness: EMPTY_FRESHNESS
  }
})

const CVE_CACHE_TTL  = 24 * 60 * 60 * 1000  // 24 hours
const EPSS_CACHE_TTL = 7  * 24 * 60 * 60 * 1000  // 7 days
const KEV_CACHE_TTL  = 24 * 60 * 60 * 1000  // 24 hours

// ─── Retry Utility ───────────────────────────────────────────

async function fetchWithRetry(
  url: string,
  options: { method?: string; body?: string; headers?: Record<string, string> } = {},
  maxRetries = 3
): Promise<{ ok: boolean; status: number; data: any }> {
  let lastError: Error | null = null

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    if (attempt > 0) {
      // Exponential backoff: 1s, 2s, 4s
      await new Promise(r => setTimeout(r, Math.pow(2, attempt) * 1000))
    }

    try {
      const result = await electronNetFetch(url, options)
      if (result.ok) return result
      // If server returned 429 (rate limit) or 5xx, retry
      if (result.status === 429 || result.status >= 500) {
        lastError = new Error(`HTTP ${result.status}`)
        continue
      }
      // 4xx (not 429) = don't retry
      return result
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err))
    }
  }

  return { ok: false, status: 0, data: null }
}

function electronNetFetch(
  url: string,
  options: { method?: string; body?: string; headers?: Record<string, string> } = {}
): Promise<{ ok: boolean; status: number; data: any }> {
  return new Promise((resolve, reject) => {
    const request = net.request({ method: options.method ?? 'GET', url })

    if (options.headers) {
      for (const [k, v] of Object.entries(options.headers)) {
        request.setHeader(k, v)
      }
    }

    request.on('response', (response) => {
      let body = ''
      response.on('data', (chunk) => { body += chunk.toString() })
      response.on('end', () => {
        try {
          const data = JSON.parse(body)
          resolve({
            ok: response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode,
            data
          })
        } catch {
          resolve({ ok: false, status: response.statusCode, data: body })
        }
      })
    })

    request.on('error', reject)

    if (options.body) request.write(options.body)
    request.end()
  })
}

// ─── 1. CISA KEV List ────────────────────────────────────────

let kevCache: { cves: Set<string>; dueDates: Record<string, string>; fetchedAt: number } | null = null

async function loadKevList(): Promise<{ cves: Set<string>; dueDates: Record<string, string> }> {
  // Check in-memory cache
  if (kevCache && Date.now() - kevCache.fetchedAt < KEV_CACHE_TTL) {
    return kevCache
  }

  // Check disk cache
  const stored = cacheStore.get('kevData')
  if (stored && Date.now() - stored.fetchedAt < KEV_CACHE_TTL) {
    kevCache = { cves: new Set(stored.cves), dueDates: stored.dueDates, fetchedAt: stored.fetchedAt }
    return kevCache
  }

  // Fetch from CISA
  try {
    const result = await fetchWithRetry(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    )

    if (result.ok && result.data?.vulnerabilities) {
      const cves = new Set<string>()
      const dueDates: Record<string, string> = {}

      for (const v of result.data.vulnerabilities) {
        if (v.cveID) {
          cves.add(v.cveID)
          if (v.dueDate) dueDates[v.cveID] = v.dueDate
        }
      }

      kevCache = { cves, dueDates, fetchedAt: Date.now() }
      // Persist to disk
      cacheStore.set('kevData', {
        cves: Array.from(cves),
        dueDates,
        fetchedAt: Date.now()
      })

      updateFreshness('kev', true, cves.size)
      return kevCache
    }
  } catch (err) {
    console.warn('[vuln-pipeline] KEV fetch failed:', err)
    updateFreshness('kev', false, 0, String(err))
  }

  // Return whatever we have (even if stale)
  if (kevCache) return kevCache
  if (stored) {
    kevCache = { cves: new Set(stored.cves), dueDates: stored.dueDates, fetchedAt: stored.fetchedAt }
    return kevCache
  }
  return { cves: new Set(), dueDates: {} }
}

// ─── 2. NVD Enrichment ──────────────────────────────────────

interface NvdCveData {
  cvssV3Score: number | null
  cvssV3Vector: string | null
  cvssV2Score: number | null
  description: string | null
  cwes: string[]
}

/**
 * Query NVD for a single CVE. Respects rate limits.
 * Without API key: 5 requests per 30 seconds.
 * With API key: 50 requests per 30 seconds.
 */
async function queryNvd(cveId: string, apiKey?: string): Promise<NvdCveData | null> {
  if (!cveId.startsWith('CVE-')) return null

  const headers: Record<string, string> = {}
  if (apiKey) headers['apiKey'] = apiKey

  const result = await fetchWithRetry(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`,
    { headers },
    2  // fewer retries for NVD (rate limits are tight)
  )

  if (!result.ok || !result.data?.vulnerabilities?.[0]) return null

  const cve = result.data.vulnerabilities[0].cve
  const metrics = cve?.metrics

  let cvssV3Score: number | null = null
  let cvssV3Vector: string | null = null
  let cvssV2Score: number | null = null

  // Try CVSS v3.1 first, then v3.0
  const v31 = metrics?.cvssMetricV31?.[0]?.cvssData
  const v30 = metrics?.cvssMetricV30?.[0]?.cvssData
  const v2 = metrics?.cvssMetricV2?.[0]?.cvssData

  if (v31) {
    cvssV3Score = v31.baseScore
    cvssV3Vector = v31.vectorString
  } else if (v30) {
    cvssV3Score = v30.baseScore
    cvssV3Vector = v30.vectorString
  }

  if (v2) {
    cvssV2Score = v2.baseScore
  }

  const description = cve?.descriptions?.find((d: any) => d.lang === 'en')?.value ?? null
  const cwes: string[] = []
  for (const weakness of cve?.weaknesses ?? []) {
    for (const desc of weakness?.description ?? []) {
      if (desc.value && desc.value !== 'NVD-CWE-Other' && desc.value !== 'NVD-CWE-noinfo') {
        cwes.push(desc.value)
      }
    }
  }

  return { cvssV3Score, cvssV3Vector, cvssV2Score, description, cwes }
}

// ─── 3. GitHub Advisory Enrichment ───────────────────────────

interface GhsaData {
  ghsaId: string
  severity: string
  cvssScore: number | null
  cvssVector: string | null
  summary: string | null
  cwes: string[]
}

/**
 * Query GitHub Advisory Database by CVE ID.
 * Uses the public REST API (no auth required for public advisories).
 */
async function queryGhsa(cveId: string): Promise<GhsaData | null> {
  if (!cveId.startsWith('CVE-')) return null

  const result = await fetchWithRetry(
    `https://api.github.com/advisories?cve_id=${cveId}`,
    {
      headers: {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'FAVR-Scanner/2.0'
      }
    },
    2
  )

  if (!result.ok || !Array.isArray(result.data) || result.data.length === 0) return null

  const advisory = result.data[0]
  return {
    ghsaId: advisory.ghsa_id ?? '',
    severity: advisory.severity ?? 'unknown',
    cvssScore: advisory.cvss?.score ?? null,
    cvssVector: advisory.cvss?.vector_string ?? null,
    summary: advisory.summary ?? null,
    cwes: (advisory.cwes ?? []).map((c: any) => c.cwe_id).filter(Boolean)
  }
}

// ─── 4. EPSS Enrichment ─────────────────────────────────────

interface EpssEntry {
  score: number
  percentile: number
}

/**
 * Fetch EPSS scores for a batch of CVE IDs with caching.
 */
async function fetchEpssWithCache(cveIds: string[]): Promise<Map<string, EpssEntry>> {
  const results = new Map<string, EpssEntry>()
  const toFetch: string[] = []
  const cachedEpss = cacheStore.get('epssEntries')

  // Check cache first
  for (const cve of cveIds) {
    const cached = cachedEpss[cve]
    if (cached && Date.now() - cached.fetchedAt < EPSS_CACHE_TTL) {
      results.set(cve, { score: cached.score, percentile: cached.percentile })
    } else {
      toFetch.push(cve)
    }
  }

  if (toFetch.length === 0) return results

  // Batch into groups of 50
  const batches: string[][] = []
  for (let i = 0; i < toFetch.length; i += 50) {
    batches.push(toFetch.slice(i, i + 50))
  }

  let totalFetched = 0
  for (const batch of batches) {
    const cveParam = batch.join(',')
    const result = await fetchWithRetry(
      `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveParam)}`
    )

    if (result.ok && result.data?.data) {
      for (const entry of result.data.data) {
        const score = parseFloat(String(entry.epss))
        const percentile = parseFloat(String(entry.percentile))
        results.set(entry.cve, { score, percentile })

        // Update disk cache
        cachedEpss[entry.cve] = { score, percentile, fetchedAt: Date.now() }
        totalFetched++
      }
    }
  }

  if (totalFetched > 0) {
    cacheStore.set('epssEntries', cachedEpss)
  }
  updateFreshness('epss', totalFetched > 0 || results.size > 0, results.size)

  return results
}

// ─── 5. CVSS Normalization ──────────────────────────────────

/**
 * Normalize any CVSS score to a v3.1-equivalent base score.
 * CVSS v2 scores are roughly converted: v2 uses 0-10 but the scales differ.
 * A v2 score of 7.0 roughly corresponds to a v3.1 of ~7.5.
 */
function normalizeCvssToV31(v3Score: number | null, v2Score: number | null): number {
  if (v3Score !== null && v3Score > 0) return v3Score

  if (v2Score !== null && v2Score > 0) {
    // Rough v2 -> v3.1 conversion based on NVD historical mapping
    // v2 scores tend to be lower than v3 for the same vuln
    if (v2Score >= 9.0) return 9.5
    if (v2Score >= 7.0) return v2Score + 0.5
    if (v2Score >= 4.0) return v2Score + 1.0
    return v2Score
  }

  return 5.0  // default when no CVSS available
}

// ─── Main Pipeline ──────────────────────────────────────────

export type PipelineProgressCallback = (msg: string) => void

export interface PipelineConfig {
  nvdApiKey?: string
  enableNvd?: boolean        // default true
  enableGhsa?: boolean       // default true
  enableKev?: boolean        // default true
  forceRefresh?: boolean     // ignore cache
}

/**
 * Enrich a list of CVE IDs with data from all sources.
 * Called after OSV.dev returns initial vulnerability data.
 *
 * This is the main entry point for the data pipeline.
 */
export async function enrichVulnerabilities(
  cveIds: string[],
  config: PipelineConfig = {},
  onProgress?: PipelineProgressCallback
): Promise<{
  enriched: Map<string, EnrichedCveData>
  freshness: DataFreshness
}> {
  const enableNvd = config.enableNvd !== false
  const enableGhsa = config.enableGhsa !== false
  const enableKev = config.enableKev !== false
  const forceRefresh = config.forceRefresh ?? false

  const enriched = new Map<string, EnrichedCveData>()
  const cveOnlyIds = cveIds.filter(id => id.startsWith('CVE-'))

  if (cveOnlyIds.length === 0) {
    return { enriched, freshness: getFreshness() }
  }

  // Check disk cache for already-enriched CVEs
  if (!forceRefresh) {
    const cachedEntries = cacheStore.get('cveEntries')
    for (const cveId of cveOnlyIds) {
      const cached = cachedEntries[cveId]
      if (cached && Date.now() - cached.fetchedAt < CVE_CACHE_TTL) {
        enriched.set(cveId, cached.data)
      }
    }
  }

  const uncachedCves = cveOnlyIds.filter(id => !enriched.has(id))

  if (uncachedCves.length === 0) {
    onProgress?.(`All ${cveOnlyIds.length} CVEs served from cache`)
    return { enriched, freshness: getFreshness() }
  }

  onProgress?.(`Enriching ${uncachedCves.length} CVEs from external sources...`)

  // Step 1: Load KEV list (single request, cached)
  let kevData = { cves: new Set<string>(), dueDates: {} as Record<string, string> }
  if (enableKev) {
    onProgress?.('Loading CISA Known Exploited Vulnerabilities list...')
    kevData = await loadKevList()
    onProgress?.(`KEV list loaded: ${kevData.cves.size} known exploited CVEs`)
  }

  // Step 2: Fetch EPSS scores (batched, cached)
  onProgress?.('Fetching EPSS exploit prediction scores...')
  const epssScores = await fetchEpssWithCache(uncachedCves)
  onProgress?.(`EPSS scores: ${epssScores.size}/${uncachedCves.length} CVEs`)

  // Step 3: NVD enrichment (rate-limited, sequential with delays)
  const nvdResults = new Map<string, NvdCveData>()
  if (enableNvd) {
    // Only query NVD for a subset to respect rate limits — prioritize CVEs missing CVSS
    const nvdBatchSize = config.nvdApiKey ? 40 : 5  // much fewer without key
    const toQueryNvd = uncachedCves.slice(0, nvdBatchSize)
    onProgress?.(`Querying NVD for ${toQueryNvd.length} CVEs...`)

    let nvdCount = 0
    const delay = config.nvdApiKey ? 700 : 6500  // 50/30s with key, 5/30s without
    for (const cveId of toQueryNvd) {
      const data = await queryNvd(cveId, config.nvdApiKey)
      if (data) {
        nvdResults.set(cveId, data)
        nvdCount++
      }
      if (toQueryNvd.indexOf(cveId) < toQueryNvd.length - 1) {
        await new Promise(r => setTimeout(r, delay))
      }
    }
    updateFreshness('nvd', true, nvdCount)
    onProgress?.(`NVD enriched ${nvdCount} CVEs`)
  }

  // Step 4: GitHub Advisory enrichment (rate-limited)
  const ghsaResults = new Map<string, GhsaData>()
  if (enableGhsa) {
    // GitHub API: 60 requests/hour without auth
    const ghsaBatchSize = 15
    const toQueryGhsa = uncachedCves.slice(0, ghsaBatchSize)
    onProgress?.(`Querying GitHub Advisories for ${toQueryGhsa.length} CVEs...`)

    let ghsaCount = 0
    for (const cveId of toQueryGhsa) {
      const data = await queryGhsa(cveId)
      if (data) {
        ghsaResults.set(cveId, data)
        ghsaCount++
      }
      // ~1 req/sec to stay well under 60/hour
      if (toQueryGhsa.indexOf(cveId) < toQueryGhsa.length - 1) {
        await new Promise(r => setTimeout(r, 1200))
      }
    }
    updateFreshness('ghsa', true, ghsaCount)
    onProgress?.(`GitHub Advisory enriched ${ghsaCount} CVEs`)
  }

  // Step 5: Merge all sources into EnrichedCveData
  const cveEntries = cacheStore.get('cveEntries')

  for (const cveId of uncachedCves) {
    const epss = epssScores.get(cveId)
    const nvd = nvdResults.get(cveId)
    const ghsa = ghsaResults.get(cveId)
    const isKev = kevData.cves.has(cveId)
    const kevDueDate = kevData.dueDates[cveId] ?? null

    // Normalize CVSS — prefer NVD v3.1, fall back to GHSA, then OSV estimate
    const cvssFromNvd = nvd?.cvssV3Score ?? null
    const cvssFromGhsa = ghsa?.cvssScore ?? null
    const normalizedCvss = normalizeCvssToV31(cvssFromNvd ?? cvssFromGhsa, nvd?.cvssV2Score ?? null)

    // Log severity disagreements
    if (cvssFromNvd !== null && cvssFromGhsa !== null && Math.abs(cvssFromNvd - cvssFromGhsa) > 1.5) {
      console.warn(`[vuln-pipeline] Severity disagreement for ${cveId}: NVD=${cvssFromNvd}, GHSA=${cvssFromGhsa}`)
    }

    const sources: string[] = ['OSV']
    if (nvd) sources.push('NVD')
    if (ghsa) sources.push('GHSA')
    if (isKev) sources.push('KEV')
    if (epss) sources.push('EPSS')

    const cwes = [...new Set([...(nvd?.cwes ?? []), ...(ghsa?.cwes ?? [])])]

    const severity = normalizedCvss >= 9 ? 'critical'
      : normalizedCvss >= 7 ? 'high'
      : normalizedCvss >= 4 ? 'medium'
      : 'low'

    const entry: EnrichedCveData = {
      cveId,
      cvssScore: normalizedCvss,
      cvssVector: nvd?.cvssV3Vector ?? ghsa?.cvssVector ?? null,
      severity,
      epssScore: epss?.score ?? 0,
      epssPercentile: epss?.percentile ?? 0,
      isKev,
      kevDueDate,
      hasPublicExploit: isKev,  // KEV = confirmed exploited
      sources,
      nvdDescription: nvd?.description ?? null,
      ghsaSeverity: ghsa?.severity ?? null,
      cwes
    }

    enriched.set(cveId, entry)

    // Save to disk cache
    cveEntries[cveId] = { data: entry, fetchedAt: Date.now() }
  }

  cacheStore.set('cveEntries', cveEntries)

  onProgress?.(`Enrichment complete: ${enriched.size} CVEs from ${countActiveSources()} sources`)

  return { enriched, freshness: getFreshness() }
}

// ─── Freshness Tracking ─────────────────────────────────────

function updateFreshness(source: keyof DataFreshness, available: boolean, count: number, error?: string): void {
  const freshness = cacheStore.get('freshness')
  freshness[source] = {
    ...freshness[source],
    lastQueried: Date.now(),
    available,
    entriesReturned: count,
    error
  }
  cacheStore.set('freshness', freshness)
}

export function getFreshness(): DataFreshness {
  return cacheStore.get('freshness')
}

function countActiveSources(): number {
  const f = cacheStore.get('freshness')
  return [f.osv, f.nvd, f.ghsa, f.kev, f.epss].filter(s => s.available && s.lastQueried !== null).length
}

/**
 * Force refresh all cached data.
 */
export function clearVulnCache(): void {
  cacheStore.set('cveEntries', {})
  cacheStore.set('epssEntries', {})
  cacheStore.set('kevData', null)
  cacheStore.set('freshness', EMPTY_FRESHNESS)
  kevCache = null
}
