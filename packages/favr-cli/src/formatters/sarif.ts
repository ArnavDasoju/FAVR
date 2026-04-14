/**
 * SARIF 2.1.0 formatter — produces GitHub Code Scanning compatible output.
 *
 * Each vulnerability maps to a SARIF result with:
 * - ruleId (CVE ID)
 * - level (error/warning/note based on severity)
 * - message (vulnerability description)
 * - locations (affected files from scan data)
 */

import type { ScanResult, Vulnerability } from '@favr/core'

interface SarifLog {
  $schema: string
  version: string
  runs: SarifRun[]
}

interface SarifRun {
  tool: { driver: SarifDriver }
  results: SarifResult[]
}

interface SarifDriver {
  name: string
  version: string
  informationUri: string
  rules: SarifRule[]
}

interface SarifRule {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription: { text: string }
  helpUri?: string
  defaultConfiguration: { level: string }
  properties: {
    tags: string[]
    precision: string
    'security-severity': string
  }
}

interface SarifResult {
  ruleId: string
  ruleIndex: number
  level: string
  message: { text: string }
  locations: SarifLocation[]
  properties: Record<string, any>
}

interface SarifLocation {
  physicalLocation: {
    artifactLocation: { uri: string; uriBaseId: string }
    region?: { startLine: number }
  }
}

function severityToLevel(severity: string): string {
  switch (severity) {
    case 'critical': return 'error'
    case 'high': return 'error'
    case 'medium': return 'warning'
    case 'low': return 'note'
    default: return 'note'
  }
}

export function formatSarif(result: ScanResult): string {
  const vulns = result.analysis.graph.vulnerabilities.filter(v => v.status === 'open')

  const rules: SarifRule[] = vulns.map(v => ({
    id: v.cveId,
    name: v.cveId.replace(/-/g, ''),
    shortDescription: { text: v.title },
    fullDescription: { text: v.description || v.title },
    helpUri: v.cveId.startsWith('CVE-')
      ? `https://nvd.nist.gov/vuln/detail/${v.cveId}`
      : `https://osv.dev/vulnerability/${v.cveId}`,
    defaultConfiguration: { level: severityToLevel(v.severity) },
    properties: {
      tags: ['security', `severity/${v.severity}`, ...v.complianceViolations.map(f => `compliance/${f}`)],
      precision: 'high',
      'security-severity': v.cvssScore.toFixed(1)
    }
  }))

  const results: SarifResult[] = vulns.map((v, i) => {
    const locations: SarifLocation[] = []

    // Use the affected package as the location hint
    // In a real scan, we'd have file-level data from the scanner
    const pkgFile = guessManifestFile(v)
    locations.push({
      physicalLocation: {
        artifactLocation: { uri: pkgFile, uriBaseId: '%SRCROOT%' },
        region: { startLine: 1 }
      }
    })

    return {
      ruleId: v.cveId,
      ruleIndex: i,
      level: severityToLevel(v.severity),
      message: {
        text: `${v.title}\n\nAffected: ${v.affectedPackage}\nFixed in: ${v.patchedVersion}\nCVSS: ${v.cvssScore} | EPSS: ${(v.epssScore * 100).toFixed(1)}%\nRemediation: ${v.remediationCost}h effort, ${v.remediationDowntime}min downtime`
      },
      locations,
      properties: {
        severity: v.severity,
        cvssScore: v.cvssScore,
        epssScore: v.epssScore,
        affectedPackage: v.affectedPackage,
        patchedVersion: v.patchedVersion,
        knownExploit: v.knownExploit,
        complianceViolations: v.complianceViolations
      }
    }
  })

  const sarif: SarifLog = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'FAVR',
          version: result.analysis.engineVersion,
          informationUri: 'https://github.com/favr-security/favr',
          rules
        }
      },
      results
    }]
  }

  return JSON.stringify(sarif, null, 2)
}

function guessManifestFile(v: Vulnerability): string {
  const pkg = v.affectedPackage.toLowerCase()
  if (pkg.includes('/') && !pkg.startsWith('@')) return 'go.mod'
  if (pkg.match(/^[a-z][a-z0-9_-]*$/i)) {
    // Could be npm or pip — check for common npm patterns
    if (pkg.includes('-') || pkg.includes('express') || pkg.includes('react')) return 'package.json'
    return 'package.json'
  }
  if (pkg.startsWith('@')) return 'package.json'
  return 'package.json'
}
