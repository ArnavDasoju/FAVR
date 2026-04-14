/**
 * Blast Radius Engine — computes downstream impact for each vulnerability patch.
 *
 * When you patch a service, dependent services may need restarts.
 * This module calculates the full cascade: which services go down,
 * how long total downtime is, and why each restart is needed.
 */

import type { AttackGraph, BlastRadius, Vulnerability } from './types.js'

/**
 * Compute blast radius for every open vulnerability.
 */
export function computeAllBlastRadii(graph: AttackGraph): Record<string, BlastRadius> {
  const result: Record<string, BlastRadius> = {}
  const openVulns = graph.vulnerabilities.filter(v => v.status === 'open')

  for (const vuln of openVulns) {
    result[vuln.id] = computeBlastRadius(graph, vuln)
  }

  return result
}

/**
 * Compute blast radius for a single vulnerability.
 */
function computeBlastRadius(graph: AttackGraph, vuln: Vulnerability): BlastRadius {
  const directServices = [...vuln.affectedServiceIds]
  const cascadeServices: string[] = []
  const cascadeRestarts: { serviceId: string; reason: string }[] = []
  const visited = new Set<string>(directServices)

  // BFS: find all services that depend on affected services (reverse adjacency)
  const queue = [...directServices]
  while (queue.length > 0) {
    const current = queue.shift()!
    const currentService = graph.services.find(s => s.id === current)

    // Services that depend on `current` (reverse adj = who depends on me)
    const dependents = graph.reverseAdjacency.get(current) ?? []
    for (const depId of dependents) {
      if (!visited.has(depId)) {
        visited.add(depId)
        cascadeServices.push(depId)
        queue.push(depId)

        const depService = graph.services.find(s => s.id === depId)
        const dep = graph.dependencies.find(d => d.from === depId && d.to === current)
        cascadeRestarts.push({
          serviceId: depId,
          reason: `${depService?.name ?? depId} depends on ${currentService?.name ?? current} via ${dep?.type ?? 'dependency'} (weight: ${dep?.propagationWeight ?? '?'})`
        })
      }
    }
  }

  // Total downtime: direct service downtime + cascade restart time (estimated 5 min per cascade)
  const directDowntime = vuln.remediationDowntime
  const cascadeDowntime = cascadeServices.length * 5  // 5 min per cascading restart
  const totalDowntimeMinutes = directDowntime + cascadeDowntime

  return {
    vulnId: vuln.id,
    directServices,
    cascadeServices,
    totalDowntimeMinutes,
    cascadeRestarts
  }
}
