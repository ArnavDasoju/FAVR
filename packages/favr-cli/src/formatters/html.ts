/**
 * HTML formatter — reuses the core engine's report generator.
 */

import { generateReport, type ScanResult } from '@favr/core'

export function formatHtml(result: ScanResult): string {
  return generateReport(result.analysis)
}
