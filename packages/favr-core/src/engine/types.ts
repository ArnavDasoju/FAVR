/**
 * FAVR Engine Types — core data structures for vulnerability analysis.
 */

// ─── Services & Dependencies ──────────────────────────────────

export interface MaintenanceWindow {
  day: 'Monday' | 'Tuesday' | 'Wednesday' | 'Thursday' | 'Friday' | 'Saturday' | 'Sunday'
  startTime: string             // HH:MM (24h)
  endTime: string               // HH:MM (24h)
  timezone: string              // e.g. 'EST'
  durationMinutes: number       // total window length
}

export type ComplianceFramework = 'PCI-DSS' | 'SOX' | 'HIPAA' | 'GDPR' | 'SOC2' | 'NIST' | 'ISO27001'

export interface Service {
  id: string
  name: string
  techStack: string[]           // e.g. ['Node.js 18', 'Express 4.18', 'PostgreSQL 15']
  tier: 'critical' | 'high' | 'medium' | 'low'
  sla: number                   // uptime % (e.g. 99.99)
  description: string
  baseCompromiseProbability: number  // 0-1, initial probability before propagation
  currentRiskScore: number          // computed after Bayesian propagation
  complianceFrameworks: ComplianceFramework[]  // regulatory frameworks this service falls under
  maintenanceWindow: MaintenanceWindow | null  // when this service can be patched
}

export interface Dependency {
  from: string  // source service ID
  to: string    // target service ID (depends on)
  type: 'api' | 'data' | 'auth' | 'shared-lib'
  propagationWeight: number  // 0-1, how much compromise propagates through this edge
  description: string
}

// ─── Vulnerabilities ──────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface Vulnerability {
  id: string
  cveId: string
  title: string
  description: string
  severity: Severity
  cvssScore: number             // 0-10
  epssScore: number             // 0-1, EPSS (Exploit Prediction Scoring System) probability
  exploitProbability: number    // 0-1, likelihood of exploitation
  affectedServiceIds: string[]
  affectedPackage: string       // e.g. 'express@4.18.2'
  patchedVersion: string        // e.g. 'express@4.19.0'
  remediationCost: number       // person-hours
  remediationDowntime: number   // minutes of expected downtime
  complexity: 'low' | 'medium' | 'high'
  status: 'open' | 'in-progress' | 'patched' | 'verified'
  patchOrder: number | null     // assigned after Monte Carlo
  constraints: VulnConstraint[]
  knownExploit: boolean         // is there a known exploit in the wild?
  complianceViolations: ComplianceFramework[]  // which frameworks this CVE violates
  complianceDeadlineDays: number | null  // days until compliance violation if unpatched
}

export interface VulnConstraint {
  type: 'maintenance-window' | 'dependency' | 'team-capacity' | 'compliance'
  description: string
  blockedBy?: string[]  // CVE IDs that must be patched first
}

// ─── Attack Graph ─────────────────────────────────────────────

export interface AttackGraph {
  services: Service[]
  dependencies: Dependency[]
  vulnerabilities: Vulnerability[]
  /** Adjacency list: serviceId -> [dependent serviceIds] */
  adjacency: Map<string, string[]>
  /** Reverse adjacency: serviceId -> [services that depend on it] */
  reverseAdjacency: Map<string, string[]>
}

// ─── Simulation Results ───────────────────────────────────────

export interface SimulationResult {
  optimalOrder: string[]        // CVE IDs in optimal patch order
  naiveOrder: string[]          // CVE IDs sorted by CVSS descending
  optimalCurve: number[]        // cumulative risk at each patch step (0 = before any patch)
  naiveCurve: number[]          // cumulative risk for naive ordering
  confidenceIntervals: ConfidenceInterval[]  // per-position confidence
  totalRiskBefore: number       // total system risk before any patching
  totalRiskAfter: number        // total system risk after all patches
  riskReduction: number         // percentage reduction
  iterations: number
  convergenceScore: number      // 0-1, how stable the ordering is
}

export interface ConfidenceInterval {
  position: number
  cveId: string
  frequency: number     // how often this CVE appeared at this position (0-1)
  alternatives: { cveId: string; frequency: number }[]  // other CVEs that appeared here
}

// ─── Pareto Optimization ──────────────────────────────────────

export interface ParetoSolution {
  id: string
  patchOrder: string[]
  totalRisk: number       // residual risk after applying this ordering
  totalCost: number       // total person-hours
  totalDowntime: number   // total minutes of downtime
  dominated: boolean      // true if this solution is dominated by another
  label?: string          // e.g. 'Optimal Risk', 'Balanced', 'Minimal Downtime'
}

export interface ParetoFrontier {
  solutions: ParetoSolution[]
  frontierIds: string[]   // IDs of non-dominated solutions
}

// ─── Blast Radius ────────────────────────────────────────────

export interface BlastRadius {
  vulnId: string
  directServices: string[]          // services directly affected by the vuln
  cascadeServices: string[]         // services indirectly affected via dependencies
  totalDowntimeMinutes: number      // total downtime across all affected services
  cascadeRestarts: { serviceId: string; reason: string }[]
}

// ─── Maintenance Schedule ────────────────────────────────────

export interface ScheduledPatch {
  vulnId: string
  serviceId: string                 // primary service being patched
  windowDay: string
  windowStart: string
  windowEnd: string
  estimatedStart: number            // minutes from schedule start
  estimatedDuration: number         // minutes
  dependsOn: string[]               // vulnIds that must be patched first
  concurrentWith: string[]          // vulnIds patched in the same window
  weekNumber: number                // which week (1, 2, 3...) this gets scheduled
}

// ─── What-If Scenario ────────────────────────────────────────

export interface WhatIfConstraints {
  maxBudgetHours: number | null     // max person-hours available
  skipServiceIds: string[]          // services to exclude from patching
  skipVulnIds: string[]             // vulns to skip
  maxDowntimeMinutes: number | null // max allowed downtime
}

export interface WhatIfResult {
  constraints: WhatIfConstraints
  patchableVulns: string[]          // vulns that can be patched within constraints
  skippedVulns: string[]            // vulns that couldn't fit
  residualRisk: number              // risk after patching what we can
  residualRiskByService: Record<string, number>
  totalCost: number
  totalDowntime: number
  complianceGaps: { framework: ComplianceFramework; vulnIds: string[] }[]
}

// ─── Analysis Result (complete output) ────────────────────────

export interface AnalysisResult {
  graph: {
    services: Service[]
    dependencies: Dependency[]
    vulnerabilities: Vulnerability[]
  }
  riskScores: Record<string, number>  // serviceId -> propagated risk
  simulation: SimulationResult
  pareto: ParetoFrontier
  blastRadii: Record<string, BlastRadius>  // vulnId -> blast radius
  schedule: ScheduledPatch[]               // maintenance-window-aware schedule
  complianceSummary: {
    frameworks: ComplianceFramework[]
    violations: { framework: ComplianceFramework; vulnIds: string[]; urgentCount: number }[]
    overallComplianceRisk: number  // 0-1
  }
  timestamp: number
  engineVersion: string
}

// ─── Progress Callback ────────────────────────────────────────

export interface AnalysisProgress {
  phase: 'graph' | 'bayesian' | 'monte-carlo' | 'pareto' | 'blast-radius' | 'scheduling' | 'compliance' | 'complete'
  progress: number  // 0-100
  message: string
}

export type ProgressCallback = (progress: AnalysisProgress) => void
