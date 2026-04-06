/**
 * Document Parser — ingests CVE feeds, dependency maps, and internal docs.
 * Extracts structured vulnerability data for the analysis engine.
 */

import { readFileSync } from 'fs'
import { extname } from 'path'
import type { Service, Dependency, Vulnerability, Severity } from '../engine/types'

export interface ParsedInput {
  services: Service[]
  dependencies: Dependency[]
  vulnerabilities: Vulnerability[]
  rawDocuments: RawDocument[]
}

export interface RawDocument {
  filename: string
  type: 'cve-feed' | 'dependency-map' | 'service-config' | 'advisory' | 'unknown'
  content: string
  parsedItems: number
}

/**
 * Parse a set of uploaded files and extract structured data.
 */
export function parseDocuments(filePaths: string[]): ParsedInput {
  const result: ParsedInput = {
    services: [],
    dependencies: [],
    vulnerabilities: [],
    rawDocuments: []
  }

  for (const filePath of filePaths) {
    const ext = extname(filePath).toLowerCase()
    const content = readFileSync(filePath, 'utf-8')
    const filename = filePath.split('/').pop() ?? filePath

    try {
      if (ext === '.json') {
        const doc = parseJsonDocument(content, filename)
        result.rawDocuments.push(doc)

        if (doc.type === 'cve-feed') {
          const vulns = extractVulnerabilitiesFromJson(content)
          result.vulnerabilities.push(...vulns)
          doc.parsedItems = vulns.length
        } else if (doc.type === 'service-config') {
          const services = extractServicesFromJson(content)
          result.services.push(...services)
          doc.parsedItems = services.length
        } else if (doc.type === 'dependency-map') {
          const deps = extractDependenciesFromJson(content)
          result.dependencies.push(...deps)
          doc.parsedItems = deps.length
        }
      } else if (ext === '.txt' || ext === '.md') {
        const vulns = extractCvesFromText(content)
        result.vulnerabilities.push(...vulns)
        result.rawDocuments.push({
          filename,
          type: vulns.length > 0 ? 'advisory' : 'unknown',
          content: content.slice(0, 500),
          parsedItems: vulns.length
        })
      }
    } catch (err) {
      result.rawDocuments.push({
        filename,
        type: 'unknown',
        content: `Parse error: ${err instanceof Error ? err.message : String(err)}`,
        parsedItems: 0
      })
    }
  }

  return result
}

/**
 * Detect JSON document type and parse accordingly.
 */
function parseJsonDocument(content: string, filename: string): RawDocument {
  const data = JSON.parse(content)

  // Detect type from structure
  if (Array.isArray(data) && data[0]?.cveId) {
    return { filename, type: 'cve-feed', content: content.slice(0, 500), parsedItems: 0 }
  }
  if (data.vulnerabilities || data.CVE_Items || data.cves) {
    return { filename, type: 'cve-feed', content: content.slice(0, 500), parsedItems: 0 }
  }
  if (Array.isArray(data) && data[0]?.techStack) {
    return { filename, type: 'service-config', content: content.slice(0, 500), parsedItems: 0 }
  }
  if (data.services) {
    return { filename, type: 'service-config', content: content.slice(0, 500), parsedItems: 0 }
  }
  if (data.dependencies || (Array.isArray(data) && data[0]?.from && data[0]?.to)) {
    return { filename, type: 'dependency-map', content: content.slice(0, 500), parsedItems: 0 }
  }

  return { filename, type: 'unknown', content: content.slice(0, 500), parsedItems: 0 }
}

/**
 * Extract vulnerabilities from a JSON CVE feed.
 */
function extractVulnerabilitiesFromJson(content: string): Vulnerability[] {
  const data = JSON.parse(content)
  const items = data.vulnerabilities ?? data.CVE_Items ?? data.cves ?? (Array.isArray(data) ? data : [])

  return items.map((item: any, i: number) => {
    const cvss = item.cvssScore ?? item.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 5.0
    return {
      id: item.id ?? `parsed-vuln-${i}`,
      cveId: item.cveId ?? item.cve?.id ?? item.id ?? `CVE-UNKNOWN-${i}`,
      title: item.title ?? item.cve?.description ?? 'Unknown vulnerability',
      description: item.description ?? '',
      severity: item.severity ?? cvssToSeverity(cvss),
      cvssScore: cvss,
      exploitProbability: item.exploitProbability ?? cvssToExploitProb(cvss),
      affectedServiceIds: item.affectedServiceIds ?? [],
      affectedPackage: item.affectedPackage ?? 'unknown',
      patchedVersion: item.patchedVersion ?? 'unknown',
      remediationCost: item.remediationCost ?? estimateCost(cvss),
      remediationDowntime: item.remediationDowntime ?? estimateDowntime(cvss),
      complexity: item.complexity ?? (cvss >= 8 ? 'high' : cvss >= 5 ? 'medium' : 'low'),
      status: item.status ?? 'open',
      patchOrder: null,
      constraints: item.constraints ?? [],
      knownExploit: item.knownExploit ?? false
    } as Vulnerability
  })
}

/**
 * Extract services from a JSON config.
 */
function extractServicesFromJson(content: string): Service[] {
  const data = JSON.parse(content)
  const items = data.services ?? (Array.isArray(data) ? data : [])

  return items.map((item: any) => ({
    id: item.id,
    name: item.name,
    techStack: item.techStack ?? [],
    tier: item.tier ?? 'medium',
    sla: item.sla ?? 99.5,
    description: item.description ?? '',
    baseCompromiseProbability: 0,
    currentRiskScore: 0
  } as Service))
}

/**
 * Extract dependencies from a JSON map.
 */
function extractDependenciesFromJson(content: string): Dependency[] {
  const data = JSON.parse(content)
  const items = data.dependencies ?? (Array.isArray(data) ? data : [])

  return items.map((item: any) => ({
    from: item.from,
    to: item.to,
    type: item.type ?? 'api',
    propagationWeight: item.propagationWeight ?? 0.5,
    description: item.description ?? ''
  } as Dependency))
}

/**
 * Extract CVE references from plain text.
 */
function extractCvesFromText(text: string): Vulnerability[] {
  const cvePattern = /CVE-\d{4}-\d{4,}/g
  const matches = [...new Set(text.match(cvePattern) ?? [])]

  return matches.map((cveId, i) => ({
    id: `text-vuln-${i}`,
    cveId,
    title: `${cveId} (extracted from document)`,
    description: extractContextAroundCve(text, cveId),
    severity: 'medium' as Severity,
    cvssScore: 5.0,
    exploitProbability: 0.3,
    affectedServiceIds: [],
    affectedPackage: 'unknown',
    patchedVersion: 'unknown',
    remediationCost: 3,
    remediationDowntime: 15,
    complexity: 'medium' as const,
    status: 'open' as const,
    patchOrder: null,
    constraints: [],
    knownExploit: false
  }))
}

function extractContextAroundCve(text: string, cveId: string): string {
  const idx = text.indexOf(cveId)
  if (idx === -1) return ''
  const start = Math.max(0, idx - 100)
  const end = Math.min(text.length, idx + cveId.length + 200)
  return text.slice(start, end).trim()
}

function cvssToSeverity(cvss: number): Severity {
  if (cvss >= 9) return 'critical'
  if (cvss >= 7) return 'high'
  if (cvss >= 4) return 'medium'
  return 'low'
}

function cvssToExploitProb(cvss: number): number {
  return Math.min(0.95, cvss / 12)
}

function estimateCost(cvss: number): number {
  if (cvss >= 9) return 4
  if (cvss >= 7) return 3
  if (cvss >= 4) return 2
  return 1
}

function estimateDowntime(cvss: number): number {
  if (cvss >= 9) return 30
  if (cvss >= 7) return 15
  if (cvss >= 4) return 10
  return 5
}
