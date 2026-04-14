/**
 * End-to-end test — runs the CLI against the fixture project.
 */

import { describe, it, expect } from 'vitest'
import { execSync } from 'child_process'
import { join } from 'path'

const CLI = join(__dirname, '..', 'dist', 'index.js')
const FIXTURE = join(__dirname, '..', 'fixtures', 'vulnerable-project')

describe('e2e CLI', () => {
  it('JSON output is valid and contains vulnerabilities', () => {
    const output = execSync(
      `node ${CLI} ${FIXTURE} --format json --no-progress 2>/dev/null`,
      { timeout: 120000, encoding: 'utf-8' }
    )

    const parsed = JSON.parse(output)
    expect(parsed.projectName).toBe('vulnerable-project')
    expect(parsed.summary.totalVulnerabilities).toBeGreaterThan(0)
    expect(parsed.vulnerabilities).toBeInstanceOf(Array)
    expect(parsed.vulnerabilities.length).toBeGreaterThan(0)
  })

  it('SARIF output has correct schema version', () => {
    const output = execSync(
      `node ${CLI} ${FIXTURE} --format sarif --no-progress 2>/dev/null`,
      { timeout: 120000, encoding: 'utf-8' }
    )

    const parsed = JSON.parse(output)
    expect(parsed.version).toBe('2.1.0')
    expect(parsed.$schema).toContain('sarif-schema-2.1.0')
    expect(parsed.runs[0].tool.driver.name).toBe('FAVR')
    expect(parsed.runs[0].results.length).toBeGreaterThan(0)
  })

  it('table output contains CVE identifiers', () => {
    const output = execSync(
      `node ${CLI} ${FIXTURE} --format table --no-progress 2>/dev/null`,
      { timeout: 120000, encoding: 'utf-8' }
    )

    expect(output).toContain('CVE-')
    expect(output).toContain('FAVR Scan Results')
  })

  it('HTML output to file works', () => {
    const tmpFile = join(__dirname, '..', 'test-output.html')
    execSync(
      `node ${CLI} ${FIXTURE} --format html --output ${tmpFile} --no-progress 2>/dev/null`,
      { timeout: 120000 }
    )

    const { readFileSync, unlinkSync } = require('fs')
    const html = readFileSync(tmpFile, 'utf-8')
    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('FAVR')
    unlinkSync(tmpFile)
  })
})
