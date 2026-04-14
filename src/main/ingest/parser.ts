/**
 * Document Parser — ingests CVE feeds, dependency maps, and internal docs.
 * Extracts structured vulnerability data for the analysis engine.
 */

import { readFileSync } from 'fs'
import { extname } from 'path'
import type { Service, Dependency, Vulnerability, Severity } from '../engine/types'
import { getCalibration } from '../engine/calibration'

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
  if (Array.isArray(data) && data.length > 0 && looksLikeCveArray(data)) {
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

  // Last resort: check if filename hints at CVE data
  const lowerName = filename.toLowerCase()
  if (lowerName.includes('cve') || lowerName.includes('vuln') || lowerName.includes('advisory')) {
    return { filename, type: 'cve-feed', content: content.slice(0, 500), parsedItems: 0 }
  }

  return { filename, type: 'unknown', content: content.slice(0, 500), parsedItems: 0 }
}

/**
 * Check if an array looks like it contains CVE/vulnerability objects.
 * Supports various naming conventions (snake_case, camelCase, various field names).
 */
function looksLikeCveArray(data: any[]): boolean {
  const first = data[0]
  if (!first || typeof first !== 'object') return false

  // Check for CVE-like identifiers
  const hasId = first.cveId || first.cve_id || first.cve ||
    (typeof first.id === 'string' && /^CVE-/i.test(first.id))

  // Check for vulnerability-related fields
  const hasSeverity = first.severity || first.cvssScore || first.cvss_score ||
    first.cvss || first.score

  // Check for package/exploit fields
  const hasPackage = first.package || first.affectedPackage || first.affected_package ||
    first.component || first.library

  return !!(hasId || (hasSeverity && hasPackage))
}

/**
 * Extract vulnerabilities from a JSON CVE feed.
 * Handles multiple naming conventions: camelCase, snake_case, and common alternatives.
 */
function extractVulnerabilitiesFromJson(content: string): Vulnerability[] {
  const data = JSON.parse(content)
  const items = data.vulnerabilities ?? data.CVE_Items ?? data.cves ?? (Array.isArray(data) ? data : [])

  return items.map((item: any, i: number) => {
    // Normalize field access: support camelCase, snake_case, and common alternatives
    const cvss = item.cvssScore ?? item.cvss_score ?? item.cvss ?? item.score ??
      item.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 5.0

    const cveId = item.cveId ?? item.cve_id ?? item.cve?.id ??
      (typeof item.id === 'string' && /^CVE-/i.test(item.id) ? item.id : null) ??
      `CVE-UNKNOWN-${i}`

    const rawSeverity = (item.severity ?? '').toLowerCase()
    const severity = (['critical', 'high', 'medium', 'low'].includes(rawSeverity)
      ? rawSeverity
      : cvssToSeverity(cvss)) as Severity

    const epss = item.epssScore ?? item.epss_score ?? item.epss ?? cvssToExploitProb(cvss)
    const knownExploit = item.knownExploit ?? item.known_exploit ??
      item.exploit_available ?? item.exploitAvailable ?? false
    const inKev = item.inKev ?? item.in_kev ?? item.kev ?? false

    const rawVector = (item.attackVector ?? item.attack_vector ?? '').toLowerCase()
    const attackVector = (['network', 'adjacent', 'local', 'physical'].includes(rawVector)
      ? rawVector : 'unknown') as Vulnerability['attackVector']

    // Support affected_packages as array of {name, version} objects
    let affectedPackage = 'unknown'
    const pkgsArray = item.affected_packages ?? item.affectedPackages
    if (Array.isArray(pkgsArray) && pkgsArray.length > 0) {
      const first = pkgsArray[0]
      const pkgName = first.name ?? first.package ?? 'unknown'
      const pkgVer = first.version ?? ''
      affectedPackage = pkgVer ? `${pkgName}@${pkgVer}` : pkgName
    } else {
      const pkg = item.affectedPackage ?? item.affected_package ??
        item.package ?? item.component ?? item.library ?? 'unknown'
      const version = item.version ?? ''
      affectedPackage = pkg.includes('@') ? pkg : (version ? `${pkg}@${version}` : pkg)
    }

    const patchedVersion = item.patchedVersion ?? item.patched_version ??
      item.fixed_version ?? item.fixedVersion ?? 'unknown'

    // Support affected_services as array of human-readable names (slugified to IDs)
    let affectedServiceIds = item.affectedServiceIds ?? item.affected_service_ids ?? []
    const affectedService = item.affectedService ?? item.affected_service ?? null
    const affectedServicesArray = item.affected_services ?? item.affectedServices
    if (Array.isArray(affectedServicesArray) && affectedServicesArray.length > 0 && affectedServiceIds.length === 0) {
      affectedServiceIds = affectedServicesArray.map((s: string) => slugify(s))
    }

    return {
      id: item.id ?? `parsed-vuln-${i}`,
      cveId,
      title: item.title ?? item.summary ?? item.name ?? item.description?.slice(0, 80) ?? `${cveId} in ${affectedPackage}`,
      description: item.description ?? item.details ?? '',
      severity,
      cvssScore: cvss,
      epssScore: epss,
      exploitProbability: item.exploitProbability ?? item.exploit_probability ??
        contextualExploitProb(cvss, knownExploit, inKev, attackVector),
      affectedServiceIds: affectedService && affectedServiceIds.length === 0
        ? [slugify(affectedService)]
        : affectedServiceIds,
      affectedPackage,
      patchedVersion,
      remediationCost: item.remediationCost ?? item.remediation_cost ?? estimateCost(cvss),
      remediationDowntime: item.remediationDowntime ?? item.remediation_downtime ?? estimateDowntime(cvss),
      complexity: item.complexity ?? (cvss >= 8 ? 'high' : cvss >= 5 ? 'medium' : 'low'),
      status: item.status ?? 'open',
      patchOrder: null,
      constraints: item.constraints ?? [],
      knownExploit,
      inKev,
      attackVector,
      hasPublicExploit: item.hasPublicExploit ?? item.has_public_exploit ??
        item.exploit_available ?? item.exploitAvailable ?? knownExploit,
      complianceViolations: item.complianceViolations ?? item.compliance_violations ?? [],
      complianceDeadlineDays: item.complianceDeadlineDays ?? item.compliance_deadline_days ?? null
    } as Vulnerability
  })
}

/** Convert a human-readable service name to a slug ID */
function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
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
    currentRiskScore: 0,
    complianceFrameworks: item.complianceFrameworks ?? [],
    maintenanceWindow: item.maintenanceWindow ?? null
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
    propagationWeight: item.propagationWeight ?? (getCalibration().dependencyTypeWeights as Record<string, number>)[item.type] ?? getCalibration().edgeWeights.direct,
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
    epssScore: 0.3,
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
    knownExploit: false,
    inKev: false,
    attackVector: 'unknown' as const,
    hasPublicExploit: false,
    complianceViolations: [],
    complianceDeadlineDays: null
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

/**
 * Compute exploit probability that factors in real-world exploitability context,
 * not just CVSS score. This prevents high-CVSS/low-EPSS vulns (e.g., local-only
 * with no known exploit) from being overranked.
 */
function contextualExploitProb(
  cvss: number,
  knownExploit: boolean,
  inKev: boolean,
  attackVector: string
): number {
  let base = cvssToExploitProb(cvss)

  // Boost for vulns with real-world exploit evidence
  if (knownExploit) base *= 1.4
  if (inKev) base *= 1.4

  // Attack vector adjustment: network vulns are higher risk, local are lower
  if (attackVector === 'network') {
    base *= 1.15
  } else if (attackVector === 'local' || attackVector === 'physical') {
    base *= 0.5
  }

  return Math.max(0.01, Math.min(0.95, base))
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
