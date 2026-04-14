/**
 * Unit tests for threshold parsing and evaluation.
 */

import { describe, it, expect } from 'vitest'
import { execSync } from 'child_process'
import { join } from 'path'

const CLI = join(__dirname, '..', 'dist', 'index.js')
const FIXTURE = join(__dirname, '..', 'fixtures', 'vulnerable-project')

describe('threshold exit codes', () => {
  it('exits 1 when criticals exist and threshold is critical', () => {
    try {
      execSync(`node ${CLI} ${FIXTURE} --format json --threshold critical --no-progress 2>/dev/null`, {
        timeout: 120000
      })
      // Should not reach here
      expect.unreachable('Should have thrown due to exit code 1')
    } catch (err: any) {
      expect(err.status).toBe(1)
    }
  })

  it('exits 0 when threshold is not exceeded', () => {
    // The fixture has no vulns above CVSS 10.1 (max is 10.0)
    const result = execSync(`node ${CLI} ${FIXTURE} --format json --threshold 10.1 --no-progress 2>/dev/null`, {
      timeout: 120000
    })
    // If we reach here, exit code was 0
    expect(result).toBeDefined()
  })

  it('exits 1 when CVSS threshold is exceeded', () => {
    try {
      execSync(`node ${CLI} ${FIXTURE} --format json --threshold 7.0 --no-progress 2>/dev/null`, {
        timeout: 120000
      })
      expect.unreachable('Should have thrown due to exit code 1')
    } catch (err: any) {
      expect(err.status).toBe(1)
    }
  })
})
