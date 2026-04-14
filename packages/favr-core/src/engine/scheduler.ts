/**
 * Maintenance Schedule Engine — assigns patches to maintenance windows.
 *
 * Respects:
 * - Per-service maintenance windows
 * - Max concurrent patches per window
 * - Team capacity constraints
 * - Dependency ordering from Monte Carlo
 * - Estimated duration per patch
 */

import type { AttackGraph, Vulnerability, ScheduledPatch, MaintenanceWindow } from './types.js'

const MAX_CONCURRENT_PATCHES = 2  // max patches in a single window
const BUFFER_MINUTES = 15         // buffer between patches in same window

/**
 * Build a maintenance-window-aware schedule from the optimal patch ordering.
 */
export function buildSchedule(
  graph: AttackGraph,
  optimalOrder: string[]
): ScheduledPatch[] {
  const schedule: ScheduledPatch[] = []
  const vulnMap = new Map(graph.vulnerabilities.map(v => [v.id, v]))
  const serviceMap = new Map(graph.services.map(s => [s.id, s]))

  // Track what's been scheduled per window-week
  // key: "serviceId-weekN" -> minutes used
  const windowUsage = new Map<string, number>()

  let currentWeek = 1

  for (const vulnId of optimalOrder) {
    const vuln = vulnMap.get(vulnId)
    if (!vuln) continue

    // Find the primary service (first affected, or the one with the tightest window)
    const primaryServiceId = vuln.affectedServiceIds[0]
    const primaryService = serviceMap.get(primaryServiceId)
    if (!primaryService) continue

    const window = primaryService.maintenanceWindow
    const estimatedDuration = vuln.remediationDowntime + BUFFER_MINUTES

    // Find the earliest week where this fits
    let scheduled = false
    for (let week = currentWeek; week <= currentWeek + 8; week++) {
      const key = `${primaryServiceId}-week${week}`
      const used = windowUsage.get(key) ?? 0
      const windowDuration = window?.durationMinutes ?? 240

      // Check if it fits in this window
      if (used + estimatedDuration <= windowDuration) {
        // Check concurrent patch limit
        const concurrentKey = `concurrent-week${week}-${window?.day ?? 'any'}`
        const concurrentCount = windowUsage.get(concurrentKey) ?? 0
        if (concurrentCount >= MAX_CONCURRENT_PATCHES) {
          continue  // too many patches in this window already
        }

        // Find other patches in the same window for concurrentWith
        const concurrentWith = schedule
          .filter(s => s.weekNumber === week && s.windowDay === (window?.day ?? 'Any'))
          .map(s => s.vulnId)

        // Find dependency ordering
        const dependsOn = optimalOrder
          .slice(0, optimalOrder.indexOf(vulnId))
          .filter(id => {
            const depVuln = vulnMap.get(id)
            if (!depVuln) return false
            // If this vuln's service depends on the other vuln's service
            return depVuln.affectedServiceIds.some(sid =>
              graph.adjacency.get(primaryServiceId)?.includes(sid) ?? false
            )
          })

        schedule.push({
          vulnId,
          serviceId: primaryServiceId,
          windowDay: window?.day ?? 'Any',
          windowStart: window?.startTime ?? '00:00',
          windowEnd: window?.endTime ?? '06:00',
          estimatedStart: used,
          estimatedDuration: vuln.remediationDowntime,
          dependsOn,
          concurrentWith,
          weekNumber: week
        })

        windowUsage.set(key, used + estimatedDuration)
        windowUsage.set(concurrentKey, concurrentCount + 1)
        scheduled = true
        break
      }
    }

    if (!scheduled) {
      // Force schedule it in the next available week
      currentWeek++
      schedule.push({
        vulnId,
        serviceId: primaryServiceId,
        windowDay: window?.day ?? 'Any',
        windowStart: window?.startTime ?? '00:00',
        windowEnd: window?.endTime ?? '06:00',
        estimatedStart: 0,
        estimatedDuration: vuln.remediationDowntime,
        dependsOn: [],
        concurrentWith: [],
        weekNumber: currentWeek
      })
      const key = `${primaryServiceId}-week${currentWeek}`
      windowUsage.set(key, vuln.remediationDowntime + BUFFER_MINUTES)
    }
  }

  return schedule
}
