/**
 * Unit tests for config file loading and validation.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { loadConfig, mergeConfigWithFlags } from '../src/config.js'
import { writeFileSync, mkdirSync, rmSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

const testDir = join(tmpdir(), `favr-config-test-${Date.now()}`)

beforeEach(() => {
  mkdirSync(testDir, { recursive: true })
})

afterEach(() => {
  rmSync(testDir, { recursive: true, force: true })
})

describe('loadConfig', () => {
  it('returns empty config when no config file exists', () => {
    const config = loadConfig(undefined, testDir)
    expect(config).toEqual({})
  })

  it('loads .favr.json', () => {
    writeFileSync(join(testDir, '.favr.json'), JSON.stringify({
      threshold: 'high',
      ignoredCves: ['CVE-2024-0001']
    }))
    const config = loadConfig(undefined, testDir)
    expect(config.threshold).toBe('high')
    expect(config.ignoredCves).toEqual(['CVE-2024-0001'])
  })

  it('loads .favr.yml', () => {
    writeFileSync(join(testDir, '.favr.yml'), `
threshold: critical
ignoredCves:
  - CVE-2024-0001
  - CVE-2024-0002
iterations: 1000
`)
    const config = loadConfig(undefined, testDir)
    expect(config.threshold).toBe('critical')
    expect(config.ignoredCves).toHaveLength(2)
    expect(config.iterations).toBe(1000)
  })

  it('loads explicit config path', () => {
    const customPath = join(testDir, 'custom-config.json')
    writeFileSync(customPath, JSON.stringify({ threshold: 'medium' }))
    const config = loadConfig(customPath, testDir)
    expect(config.threshold).toBe('medium')
  })

  it('throws on missing explicit path', () => {
    expect(() => loadConfig('/nonexistent/config.json', testDir)).toThrow('Config file not found')
  })

  it('throws on invalid JSON', () => {
    writeFileSync(join(testDir, '.favr.json'), '{not valid json')
    expect(() => loadConfig(undefined, testDir)).toThrow('Invalid JSON')
  })

  it('throws on invalid ignoredCves type', () => {
    writeFileSync(join(testDir, '.favr.json'), JSON.stringify({
      ignoredCves: 'not-an-array'
    }))
    expect(() => loadConfig(undefined, testDir)).toThrow('must be an array')
  })

  it('throws on invalid iterations', () => {
    writeFileSync(join(testDir, '.favr.json'), JSON.stringify({
      iterations: -1
    }))
    expect(() => loadConfig(undefined, testDir)).toThrow('must be a positive number')
  })
})

describe('mergeConfigWithFlags', () => {
  it('CLI flags override config values', () => {
    const config = { threshold: 'medium', iterations: 500 }
    const merged = mergeConfigWithFlags(config, { threshold: 'high' })
    expect(merged.threshold).toBe('high')
    expect(merged.iterations).toBe(500) // unchanged
  })

  it('preserves config values when flags are absent', () => {
    const config = { threshold: 'low', ignoredCves: ['CVE-1'] }
    const merged = mergeConfigWithFlags(config, {})
    expect(merged.threshold).toBe('low')
    expect(merged.ignoredCves).toEqual(['CVE-1'])
  })
})
