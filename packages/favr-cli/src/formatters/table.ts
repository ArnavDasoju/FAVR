/**
 * Table formatter — colored terminal output using cli-table3 and chalk.
 */

import chalk from 'chalk'
import Table from 'cli-table3'
import type { ScanResult } from '@favr/core'

const severityColor: Record<string, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue
}

export function formatTable(result: ScanResult): string {
  const { analysis, discoveryStats, projectName } = result
  const vulns = analysis.graph.vulnerabilities.filter(v => v.status === 'open')

  const lines: string[] = []

  // Header
  lines.push('')
  lines.push(chalk.bold.cyan(`  FAVR Scan Results — ${projectName}`))
  lines.push(chalk.dim(`  ${'─'.repeat(50)}`))

  // Summary stats
  const critCount = vulns.filter(v => v.severity === 'critical').length
  const highCount = vulns.filter(v => v.severity === 'high').length
  const medCount = vulns.filter(v => v.severity === 'medium').length
  const lowCount = vulns.filter(v => v.severity === 'low').length

  lines.push(`  ${chalk.dim('Services:')}    ${discoveryStats.servicesFound}`)
  lines.push(`  ${chalk.dim('Packages:')}    ${discoveryStats.packagesScanned}`)
  lines.push(`  ${chalk.dim('Vulns:')}       ${vulns.length} (${chalk.bgRed.white(` ${critCount} critical `)} ${chalk.red(`${highCount} high`)} ${chalk.yellow(`${medCount} medium`)} ${chalk.blue(`${lowCount} low`)})`)
  lines.push(`  ${chalk.dim('Risk reduction:')} ${chalk.green(`${analysis.simulation.riskReduction.toFixed(1)}%`)} with optimal patching`)
  lines.push('')

  if (vulns.length === 0) {
    lines.push(chalk.green('  ✓ No vulnerabilities found!'))
    return lines.join('\n')
  }

  // Priority patches table
  lines.push(chalk.bold('  Priority Patches (optimal order):'))
  lines.push('')

  const table = new Table({
    head: ['#', 'CVE', 'Severity', 'CVSS', 'EPSS', 'Package', 'Title'].map(h => chalk.dim(h)),
    style: { head: [], border: ['dim'] },
    colWidths: [4, 18, 12, 7, 8, 22, 35]
  })

  const orderedVulns = analysis.simulation.optimalOrder
    .map(id => vulns.find(v => v.id === id))
    .filter(Boolean)

  const displayVulns = (orderedVulns.length > 0 ? orderedVulns : vulns).slice(0, 15)

  for (let i = 0; i < displayVulns.length; i++) {
    const v = displayVulns[i]!
    const colorFn = severityColor[v.severity] ?? chalk.white
    table.push([
      String(i + 1),
      v.cveId,
      colorFn(v.severity.toUpperCase()),
      v.cvssScore.toFixed(1),
      (v.epssScore * 100).toFixed(1) + '%',
      v.affectedPackage.length > 20 ? v.affectedPackage.slice(0, 18) + '..' : v.affectedPackage,
      v.title.length > 33 ? v.title.slice(0, 31) + '..' : v.title
    ])
  }

  lines.push(table.toString())

  if (vulns.length > 15) {
    lines.push(chalk.dim(`  ... and ${vulns.length - 15} more`))
  }

  return lines.join('\n')
}
