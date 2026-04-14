/**
 * Config file loader — supports .favr.yml, .favr.yaml, and .favr.json.
 *
 * Config keys:
 *   ignoredCves: string[]         — CVE IDs to skip
 *   patchingCosts: Record<string, number> — cost overrides per CVE
 *   riskModel: string             — risk model variant
 *   complianceStandards: string[] — compliance frameworks to check
 *   notifications: object         — notification settings
 *   threshold: string             — severity or CVSS threshold
 *   iterations: number            — Monte Carlo iterations
 */

import { existsSync, readFileSync } from 'fs'
import { join } from 'path'
import yaml from 'js-yaml'

export interface FavrConfig {
  ignoredCves?: string[]
  patchingCosts?: Record<string, number>
  riskModel?: string
  complianceStandards?: string[]
  notifications?: Record<string, any>
  threshold?: string
  iterations?: number
}

const CONFIG_FILES = ['.favr.yml', '.favr.yaml', '.favr.json']

/**
 * Load config from an explicit path or auto-discover in the project root.
 */
export function loadConfig(explicitPath: string | undefined, projectDir: string): FavrConfig {
  if (explicitPath) {
    if (!existsSync(explicitPath)) {
      throw new Error(`Config file not found: ${explicitPath}`)
    }
    return parseConfigFile(explicitPath)
  }

  // Auto-discover
  for (const name of CONFIG_FILES) {
    const path = join(projectDir, name)
    if (existsSync(path)) {
      return parseConfigFile(path)
    }
  }

  return {}
}

function parseConfigFile(path: string): FavrConfig {
  const content = readFileSync(path, 'utf-8')

  let parsed: any
  if (path.endsWith('.json')) {
    try {
      parsed = JSON.parse(content)
    } catch (err) {
      throw new Error(`Invalid JSON in ${path}: ${(err as Error).message}`)
    }
  } else {
    try {
      parsed = yaml.load(content)
    } catch (err) {
      throw new Error(`Invalid YAML in ${path}: ${(err as Error).message}`)
    }
  }

  if (!parsed || typeof parsed !== 'object') {
    return {}
  }

  return validateConfig(parsed, path)
}

function validateConfig(raw: Record<string, any>, path: string): FavrConfig {
  const config: FavrConfig = {}

  if (raw.ignoredCves !== undefined) {
    if (!Array.isArray(raw.ignoredCves) || !raw.ignoredCves.every((c: any) => typeof c === 'string')) {
      throw new Error(`${path}: "ignoredCves" must be an array of strings`)
    }
    config.ignoredCves = raw.ignoredCves
  }

  if (raw.patchingCosts !== undefined) {
    if (typeof raw.patchingCosts !== 'object' || Array.isArray(raw.patchingCosts)) {
      throw new Error(`${path}: "patchingCosts" must be an object mapping CVE IDs to numbers`)
    }
    config.patchingCosts = raw.patchingCosts
  }

  if (raw.riskModel !== undefined) {
    if (typeof raw.riskModel !== 'string') {
      throw new Error(`${path}: "riskModel" must be a string`)
    }
    config.riskModel = raw.riskModel
  }

  if (raw.complianceStandards !== undefined) {
    if (!Array.isArray(raw.complianceStandards)) {
      throw new Error(`${path}: "complianceStandards" must be an array of strings`)
    }
    config.complianceStandards = raw.complianceStandards
  }

  if (raw.notifications !== undefined) {
    config.notifications = raw.notifications
  }

  if (raw.threshold !== undefined) {
    if (typeof raw.threshold !== 'string' && typeof raw.threshold !== 'number') {
      throw new Error(`${path}: "threshold" must be a severity label or CVSS score`)
    }
    config.threshold = String(raw.threshold)
  }

  if (raw.iterations !== undefined) {
    if (typeof raw.iterations !== 'number' || raw.iterations < 1) {
      throw new Error(`${path}: "iterations" must be a positive number`)
    }
    config.iterations = raw.iterations
  }

  return config
}

/**
 * Merge config file values with CLI flags. CLI flags take precedence.
 */
export function mergeConfigWithFlags(config: FavrConfig, flags: Record<string, any>): FavrConfig {
  return {
    ...config,
    ...(flags.threshold ? { threshold: flags.threshold } : {}),
    ...(flags.iterations ? { iterations: flags.iterations } : {})
  }
}
