/**
 * Analysis Calibration — configurable parameters for real-world calibration.
 *
 * Centralizes all tunable constants so security engineers can adjust the model
 * to match their risk appetite and organizational context.
 */

// ─── Risk Model Presets ──────────────────────────────────────

export type RiskModel = 'conservative' | 'balanced' | 'aggressive'

export interface CalibrationConfig {
  /** Risk model preset */
  riskModel: RiskModel

  // ─── Edge Weight Defaults (10.1) ─────────────────────────
  /** Weights by dependency relationship type */
  edgeWeights: {
    /** Direct runtime dependency (e.g., express in package.json) */
    direct: number
    /** Transitive dependency, 1 hop away */
    transitive1: number
    /** Transitive dependency, 2+ hops away */
    transitive2Plus: number
    /** Dev-only dependency (devDependencies, test fixtures) */
    dev: number
  }

  /** Weights by dependency semantic type (service-to-service) */
  dependencyTypeWeights: {
    auth: number
    data: number
    api: number
    'shared-lib': number
  }

  // ─── EPSS Integration (10.2) ─────────────────────────────
  /** Weight of EPSS score in the exploit probability blend (remainder goes to CVSS-derived) */
  epssWeight: number

  // ─── Exploitability Context (10.3) ────────────────────────
  /** Multiplier when a public exploit/PoC exists */
  knownExploitMultiplier: number
  /** Multiplier when CVE is in CISA KEV catalog */
  kevMultiplier: number
  /** Multiplier for remotely exploitable (CVSS AV:N) vs local */
  remoteExploitMultiplier: number
  /** Perturbation range for Monte Carlo (±fraction) */
  perturbationRange: number
  /** Minimum perturbation floor for high-confidence threats */
  perturbationFloorHighConfidence: number

  // ─── Patching Cost Estimation (10.4) ──────────────────────
  patchingCosts: {
    /** Minor version bump (e.g., 4.18.1 → 4.18.2) */
    minorBump: number
    /** Major version bump (e.g., 4.x → 5.x) */
    majorBump: number
    /** Breaking change detected */
    breakingChange: number
    /** No patch available — mitigation only */
    mitigateOnly: number
    /** Fallback when version analysis fails */
    fallback: number
  }

  // ─── Confidence Intervals (10.5) ──────────────────────────
  /** Percentile for lower bound (e.g., 0.05 = 5th percentile) */
  confidenceLower: number
  /** Percentile for upper bound (e.g., 0.95 = 95th percentile) */
  confidenceUpper: number

  // ─── Unknown Factor Handling (10.7) ───────────────────────
  /** Base risk assigned to vulnerabilities with missing/unknown data */
  unknownFactorWeight: number
  /** Minimum exploit probability floor */
  minExploitProbability: number
}

// ─── Preset Configurations ───────────────────────────────────

/**
 * Conservative: Assumes worst case for unknowns. Use when:
 * - Handling sensitive data (financial, healthcare)
 * - Regulatory compliance is critical
 * - Zero tolerance for false negatives
 */
const CONSERVATIVE: CalibrationConfig = {
  riskModel: 'conservative',

  edgeWeights: {
    direct: 0.95,
    transitive1: 0.75,
    transitive2Plus: 0.5,
    dev: 0.25,
  },

  dependencyTypeWeights: {
    auth: 0.95,
    data: 0.90,
    api: 0.80,
    'shared-lib': 0.70,
  },

  epssWeight: 0.7,

  knownExploitMultiplier: 2.5,
  kevMultiplier: 2.0,
  remoteExploitMultiplier: 1.5,
  perturbationRange: 0.15,
  perturbationFloorHighConfidence: 0.6,

  patchingCosts: {
    minorBump: 2,
    majorBump: 6,
    breakingChange: 12,
    mitigateOnly: 16,
    fallback: 6,
  },

  confidenceLower: 0.05,
  confidenceUpper: 0.95,

  unknownFactorWeight: 0.7,
  minExploitProbability: 0.15,
}

/**
 * Balanced: Default model. Reflects empirical data without
 * over- or under-weighting unknowns.
 */
const BALANCED: CalibrationConfig = {
  riskModel: 'balanced',

  edgeWeights: {
    direct: 0.9,
    transitive1: 0.6,
    transitive2Plus: 0.3,
    dev: 0.1,
  },

  dependencyTypeWeights: {
    auth: 0.85,
    data: 0.80,
    api: 0.70,
    'shared-lib': 0.50,
  },

  epssWeight: 0.6,

  knownExploitMultiplier: 2.0,
  kevMultiplier: 1.8,
  remoteExploitMultiplier: 1.3,
  perturbationRange: 0.2,
  perturbationFloorHighConfidence: 0.5,

  patchingCosts: {
    minorBump: 1,
    majorBump: 4,
    breakingChange: 8,
    mitigateOnly: 12,
    fallback: 3,
  },

  confidenceLower: 0.05,
  confidenceUpper: 0.95,

  unknownFactorWeight: 0.5,
  minExploitProbability: 0.05,
}

/**
 * Aggressive: Only flags high-confidence threats. Use when:
 * - Engineering bandwidth is scarce
 * - Tolerating some risk to move fast
 * - Focused on actively exploited vulns only
 */
const AGGRESSIVE: CalibrationConfig = {
  riskModel: 'aggressive',

  edgeWeights: {
    direct: 0.85,
    transitive1: 0.45,
    transitive2Plus: 0.15,
    dev: 0.05,
  },

  dependencyTypeWeights: {
    auth: 0.75,
    data: 0.70,
    api: 0.55,
    'shared-lib': 0.35,
  },

  epssWeight: 0.5,

  knownExploitMultiplier: 1.5,
  kevMultiplier: 1.4,
  remoteExploitMultiplier: 1.15,
  perturbationRange: 0.25,
  perturbationFloorHighConfidence: 0.4,

  patchingCosts: {
    minorBump: 1,
    majorBump: 3,
    breakingChange: 6,
    mitigateOnly: 8,
    fallback: 2,
  },

  confidenceLower: 0.10,
  confidenceUpper: 0.90,

  unknownFactorWeight: 0.3,
  minExploitProbability: 0.02,
}

const PRESETS: Record<RiskModel, CalibrationConfig> = {
  conservative: CONSERVATIVE,
  balanced: BALANCED,
  aggressive: AGGRESSIVE,
}

// ─── Active Configuration ────────────────────────────────────

let activeConfig: CalibrationConfig = { ...BALANCED }

export function getCalibration(): CalibrationConfig {
  return activeConfig
}

export function setCalibration(model: RiskModel): CalibrationConfig {
  activeConfig = { ...PRESETS[model] }
  return activeConfig
}

export function setCustomCalibration(config: Partial<CalibrationConfig>): CalibrationConfig {
  activeConfig = { ...activeConfig, ...config }
  return activeConfig
}

export function getPreset(model: RiskModel): CalibrationConfig {
  return { ...PRESETS[model] }
}

export function getAvailableModels(): RiskModel[] {
  return ['conservative', 'balanced', 'aggressive']
}
