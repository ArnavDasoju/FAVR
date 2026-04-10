/**
 * Meridian Financial Services — Synthetic Demo Scenario
 *
 * A mid-sized fintech company (~500 employees) providing B2B financial
 * services for regional banks and credit unions. Cloud-native architecture
 * with 5 interconnected services.
 *
 * All CVEs are REAL and mapped to the tech stack.
 */

import type { Service, Dependency, Vulnerability } from '../engine/types'

// ─── Services ─────────────────────────────────────────────────

export const MERIDIAN_SERVICES: Service[] = [
  {
    id: 'payment-api',
    name: 'Payment API',
    techStack: ['Node.js 18.17', 'Express 4.18.2', 'PostgreSQL 15.3', 'jsonwebtoken 9.0.0'],
    tier: 'critical',
    sla: 99.99,
    description: 'Core transaction processing. Handles ~50K transactions/day. Zero downtime tolerance.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['PCI-DSS', 'SOX'],
    maintenanceWindow: { day: 'Saturday', startTime: '02:00', endTime: '06:00', timezone: 'EST', durationMinutes: 240 }
  },
  {
    id: 'customer-portal',
    name: 'Customer Portal',
    techStack: ['React 18.2', 'Next.js 14.0.3', 'nginx 1.24.0', 'axios 1.5.0'],
    tier: 'high',
    sla: 99.9,
    description: 'Client-facing dashboard. 8K daily active users. Account management and reporting.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['GDPR', 'SOC2'],
    maintenanceWindow: { day: 'Sunday', startTime: '00:00', endTime: '06:00', timezone: 'EST', durationMinutes: 360 }
  },
  {
    id: 'internal-dashboard',
    name: 'Internal Dashboard',
    techStack: ['Python 3.11', 'Flask 2.3.2', 'Redis 7.0.11', 'Jinja2 3.1.2'],
    tier: 'medium',
    sla: 99.5,
    description: 'Employee analytics and monitoring. Used by ~100 internal staff.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['SOC2'],
    maintenanceWindow: { day: 'Wednesday', startTime: '22:00', endTime: '02:00', timezone: 'EST', durationMinutes: 240 }
  },
  {
    id: 'auth-service',
    name: 'Auth Service',
    techStack: ['Go 1.21', 'golang-jwt/jwt 5.0.0', 'OAuth2', 'HashiCorp Vault 1.14'],
    tier: 'critical',
    sla: 99.99,
    description: 'Centralized authentication. Every service depends on it. JWT issuance and validation.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['PCI-DSS', 'SOX', 'HIPAA'],
    maintenanceWindow: { day: 'Saturday', startTime: '02:00', endTime: '06:00', timezone: 'EST', durationMinutes: 240 }
  },
  {
    id: 'database-layer',
    name: 'Database Layer',
    techStack: ['PostgreSQL 15.3', 'pgBouncer 1.20', 'AWS RDS'],
    tier: 'critical',
    sla: 99.99,
    description: 'Central data store. Payment API and Auth Service have direct dependencies.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['PCI-DSS', 'SOX', 'HIPAA', 'GDPR'],
    maintenanceWindow: { day: 'Saturday', startTime: '02:00', endTime: '06:00', timezone: 'EST', durationMinutes: 240 }
  }
]

// ─── Dependencies ─────────────────────────────────────────────

export const MERIDIAN_DEPENDENCIES: Dependency[] = [
  {
    from: 'payment-api',
    to: 'auth-service',
    type: 'auth',
    propagationWeight: 0.85,
    description: 'Payment API authenticates all requests through Auth Service'
  },
  {
    from: 'payment-api',
    to: 'database-layer',
    type: 'data',
    propagationWeight: 0.9,
    description: 'Payment API reads/writes transaction data'
  },
  {
    from: 'customer-portal',
    to: 'auth-service',
    type: 'auth',
    propagationWeight: 0.8,
    description: 'Customer Portal authenticates users through Auth Service'
  },
  {
    from: 'customer-portal',
    to: 'payment-api',
    type: 'api',
    propagationWeight: 0.6,
    description: 'Customer Portal reads transaction data (read-only API calls)'
  },
  {
    from: 'internal-dashboard',
    to: 'auth-service',
    type: 'auth',
    propagationWeight: 0.7,
    description: 'Internal Dashboard authenticates employees through Auth Service'
  },
  {
    from: 'internal-dashboard',
    to: 'database-layer',
    type: 'data',
    propagationWeight: 0.5,
    description: 'Internal Dashboard reads analytics data (read-only)'
  },
  {
    from: 'auth-service',
    to: 'database-layer',
    type: 'data',
    propagationWeight: 0.85,
    description: 'Auth Service stores user credentials and sessions'
  }
]

// ─── Vulnerabilities (Real CVEs) ──────────────────────────────

export const MERIDIAN_VULNERABILITIES: Vulnerability[] = [
  // ── CRITICAL ────────────────────────────────────────────────

  {
    id: 'vuln-001',
    cveId: 'CVE-2024-21896',
    title: 'Node.js Path Traversal via Buffer',
    description: 'A vulnerability in Node.js allows an attacker to perform path traversal by using a Buffer as a URL path. This can lead to reading arbitrary files on the system.',
    severity: 'critical',
    cvssScore: 9.8,
    epssScore: 0.87,
    exploitProbability: 0.75,
    affectedServiceIds: ['payment-api'],
    affectedPackage: 'node@18.17.0',
    patchedVersion: 'node@18.19.1',
    remediationCost: 4,
    remediationDowntime: 30,
    complexity: 'medium',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'compliance', description: 'PCI-DSS requires immediate patching of critical RCE vulnerabilities' },
      { type: 'maintenance-window', description: 'Payment API requires Saturday 2AM-6AM maintenance window' }
    ],
    knownExploit: true,
    complianceViolations: ['PCI-DSS', 'SOX'],
    complianceDeadlineDays: 7
  },
  {
    id: 'vuln-002',
    cveId: 'CVE-2024-29041',
    title: 'Express.js Open Redirect Vulnerability',
    description: 'Express versions before 4.19.2 are vulnerable to open redirect attacks. An attacker could craft a URL that redirects users to malicious sites.',
    severity: 'critical',
    cvssScore: 9.1,
    epssScore: 0.42,
    exploitProbability: 0.7,
    affectedServiceIds: ['payment-api'],
    affectedPackage: 'express@4.18.2',
    patchedVersion: 'express@4.19.2',
    remediationCost: 3,
    remediationDowntime: 15,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'dependency', description: 'Express upgrade may break middleware used by Customer Portal API proxy', blockedBy: [] },
      { type: 'compliance', description: 'PCI-DSS critical patch' }
    ],
    knownExploit: true,
    complianceViolations: ['PCI-DSS'],
    complianceDeadlineDays: 14
  },
  {
    id: 'vuln-003',
    cveId: 'CVE-2023-44487',
    title: 'HTTP/2 Rapid Reset Attack (DoS)',
    description: 'The HTTP/2 protocol allows rapid stream creation and cancellation, enabling denial of service. Affects all Go HTTP/2 servers.',
    severity: 'critical',
    cvssScore: 7.5,
    epssScore: 0.94,
    exploitProbability: 0.8,
    affectedServiceIds: ['auth-service'],
    affectedPackage: 'golang.org/x/net@0.15.0',
    patchedVersion: 'golang.org/x/net@0.17.0',
    remediationCost: 2,
    remediationDowntime: 20,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'compliance', description: 'Auth Service downtime requires coordinated restart of all dependent services' }
    ],
    knownExploit: true,
    complianceViolations: ['PCI-DSS', 'HIPAA'],
    complianceDeadlineDays: 7
  },
  {
    id: 'vuln-004',
    cveId: 'CVE-2024-21626',
    title: 'Container Escape via runc (Leaky Vessels)',
    description: 'A container escape vulnerability in runc allows attackers to break out of containers and access the host filesystem. Affects all containerized services.',
    severity: 'critical',
    cvssScore: 8.6,
    epssScore: 0.72,
    exploitProbability: 0.5,
    affectedServiceIds: ['payment-api', 'auth-service', 'database-layer'],
    affectedPackage: 'runc@1.1.9',
    patchedVersion: 'runc@1.1.12',
    remediationCost: 6,
    remediationDowntime: 45,
    complexity: 'high',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'maintenance-window', description: 'Requires coordinated restart of all container hosts' },
      { type: 'team-capacity', description: 'DevOps team of 3 needed for container infrastructure changes' }
    ],
    knownExploit: true,
    complianceViolations: ['PCI-DSS', 'SOX', 'HIPAA'],
    complianceDeadlineDays: 14
  },

  // ── HIGH ────────────────────────────────────────────────────

  {
    id: 'vuln-005',
    cveId: 'CVE-2024-24790',
    title: 'Go net/netip Incorrect IPv4-Mapped IPv6 Handling',
    description: 'Mishandling of IPv4-mapped IPv6 addresses in Go can cause incorrect behavior in network operations, potentially bypassing access controls.',
    severity: 'high',
    cvssScore: 7.3,
    epssScore: 0.08,
    exploitProbability: 0.45,
    affectedServiceIds: ['auth-service'],
    affectedPackage: 'go@1.21.0',
    patchedVersion: 'go@1.21.11',
    remediationCost: 3,
    remediationDowntime: 20,
    complexity: 'medium',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    complianceViolations: [],
    complianceDeadlineDays: null
  },
  {
    id: 'vuln-006',
    cveId: 'CVE-2024-39338',
    title: 'Axios Server-Side Request Forgery (SSRF)',
    description: 'Axios versions before 1.7.4 are vulnerable to SSRF when the base URL points to a domain controlled by the attacker.',
    severity: 'high',
    cvssScore: 7.5,
    epssScore: 0.68,
    exploitProbability: 0.55,
    affectedServiceIds: ['customer-portal'],
    affectedPackage: 'axios@1.5.0',
    patchedVersion: 'axios@1.7.4',
    remediationCost: 2,
    remediationDowntime: 10,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: true,
    complianceViolations: ['GDPR'],
    complianceDeadlineDays: 30
  },
  {
    id: 'vuln-007',
    cveId: 'CVE-2024-34351',
    title: 'Next.js Server-Side Request Forgery',
    description: 'Next.js before 14.1.1 is vulnerable to SSRF via Server Actions. Attackers can make the server send requests to internal services.',
    severity: 'high',
    cvssScore: 7.5,
    epssScore: 0.31,
    exploitProbability: 0.6,
    affectedServiceIds: ['customer-portal'],
    affectedPackage: 'next@14.0.3',
    patchedVersion: 'next@14.1.1',
    remediationCost: 4,
    remediationDowntime: 15,
    complexity: 'medium',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'dependency', description: 'Next.js upgrade requires testing all server-side rendered pages' }
    ],
    knownExploit: false,
    complianceViolations: ['SOC2'],
    complianceDeadlineDays: 30
  },
  {
    id: 'vuln-008',
    cveId: 'CVE-2023-44270',
    title: 'nginx HTTP Request Smuggling',
    description: 'nginx before 1.25.3 is vulnerable to HTTP request smuggling when used as a reverse proxy with certain backend configurations.',
    severity: 'high',
    cvssScore: 7.0,
    epssScore: 0.12,
    exploitProbability: 0.4,
    affectedServiceIds: ['customer-portal'],
    affectedPackage: 'nginx@1.24.0',
    patchedVersion: 'nginx@1.25.3',
    remediationCost: 3,
    remediationDowntime: 10,
    complexity: 'medium',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'dependency', description: 'nginx config changes require validation of reverse proxy rules' }
    ],
    knownExploit: false,
    complianceViolations: [],
    complianceDeadlineDays: null
  },

  // ── MEDIUM ──────────────────────────────────────────────────

  {
    id: 'vuln-009',
    cveId: 'CVE-2023-46136',
    title: 'Werkzeug/Flask Debugger RCE via Crafted Request',
    description: 'Werkzeug (used by Flask) debugger can be exploited if exposed in production. Allows remote code execution through crafted requests.',
    severity: 'medium',
    cvssScore: 6.5,
    epssScore: 0.73,
    exploitProbability: 0.35,
    affectedServiceIds: ['internal-dashboard'],
    affectedPackage: 'werkzeug@2.3.6',
    patchedVersion: 'werkzeug@3.0.1',
    remediationCost: 2,
    remediationDowntime: 10,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    complianceViolations: ['SOC2'],
    complianceDeadlineDays: 60
  },
  {
    id: 'vuln-010',
    cveId: 'CVE-2023-46695',
    title: 'Jinja2 Template Injection',
    description: 'Jinja2 before 3.1.3 allows template injection in certain edge cases where user input is rendered without proper sandboxing.',
    severity: 'medium',
    cvssScore: 6.1,
    epssScore: 0.05,
    exploitProbability: 0.3,
    affectedServiceIds: ['internal-dashboard'],
    affectedPackage: 'jinja2@3.1.2',
    patchedVersion: 'jinja2@3.1.3',
    remediationCost: 1,
    remediationDowntime: 5,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    complianceViolations: [],
    complianceDeadlineDays: null
  },
  {
    id: 'vuln-011',
    cveId: 'CVE-2023-28856',
    title: 'Redis AUTH Command Denial of Service',
    description: 'Redis before 7.0.12 allows remote attackers to cause a denial of service by sending specially crafted AUTH commands.',
    severity: 'medium',
    cvssScore: 5.5,
    epssScore: 0.22,
    exploitProbability: 0.3,
    affectedServiceIds: ['internal-dashboard'],
    affectedPackage: 'redis@7.0.11',
    patchedVersion: 'redis@7.0.12',
    remediationCost: 2,
    remediationDowntime: 15,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    complianceViolations: [],
    complianceDeadlineDays: null
  },
  {
    id: 'vuln-012',
    cveId: 'CVE-2024-0985',
    title: 'PostgreSQL Non-Owner REFRESH MATERIALIZED VIEW Privilege Escalation',
    description: 'PostgreSQL allows non-owner users to execute arbitrary SQL during REFRESH MATERIALIZED VIEW, leading to privilege escalation.',
    severity: 'medium',
    cvssScore: 6.8,
    epssScore: 0.04,
    exploitProbability: 0.25,
    affectedServiceIds: ['database-layer'],
    affectedPackage: 'postgresql@15.3',
    patchedVersion: 'postgresql@15.6',
    remediationCost: 5,
    remediationDowntime: 30,
    complexity: 'high',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'maintenance-window', description: 'Database upgrade requires Saturday maintenance window' },
      { type: 'compliance', description: 'PCI-DSS requires tested backup before database upgrades' }
    ],
    knownExploit: false,
    complianceViolations: ['PCI-DSS', 'HIPAA'],
    complianceDeadlineDays: 30
  },

  // ── LOW ─────────────────────────────────────────────────────

  {
    id: 'vuln-013',
    cveId: 'CVE-2023-39533',
    title: 'pgBouncer STARTTLS Stripping',
    description: 'pgBouncer before 1.21 allows STARTTLS stripping, potentially exposing database traffic to eavesdropping on untrusted networks.',
    severity: 'low',
    cvssScore: 3.7,
    epssScore: 0.02,
    exploitProbability: 0.15,
    affectedServiceIds: ['database-layer'],
    affectedPackage: 'pgbouncer@1.20.0',
    patchedVersion: 'pgbouncer@1.21.0',
    remediationCost: 1,
    remediationDowntime: 10,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    complianceViolations: ['GDPR'],
    complianceDeadlineDays: 90
  },
  {
    id: 'vuln-014',
    cveId: 'CVE-2024-22365',
    title: 'HashiCorp Vault Audit Log Bypass',
    description: 'Vault before 1.15.4 allows certain requests to bypass audit logging, potentially hiding attacker activity.',
    severity: 'low',
    cvssScore: 4.0,
    epssScore: 0.03,
    exploitProbability: 0.1,
    affectedServiceIds: ['auth-service'],
    affectedPackage: 'vault@1.14.0',
    patchedVersion: 'vault@1.15.4',
    remediationCost: 2,
    remediationDowntime: 15,
    complexity: 'medium',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    complianceViolations: ['HIPAA', 'SOX'],
    complianceDeadlineDays: 60
  },
  {
    id: 'vuln-015',
    cveId: 'CVE-2023-45853',
    title: 'jsonwebtoken Timing Attack on Token Verification',
    description: 'jsonwebtoken before 9.0.2 is vulnerable to timing attacks during token verification, potentially allowing token forgery.',
    severity: 'low',
    cvssScore: 3.1,
    epssScore: 0.01,
    exploitProbability: 0.1,
    affectedServiceIds: ['payment-api', 'auth-service'],
    affectedPackage: 'jsonwebtoken@9.0.0',
    patchedVersion: 'jsonwebtoken@9.0.2',
    remediationCost: 1,
    remediationDowntime: 5,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    complianceViolations: ['PCI-DSS'],
    complianceDeadlineDays: 90
  }
]

// ─── Constraints ──────────────────────────────────────────────

export const MERIDIAN_CONSTRAINTS = {
  maintenanceWindow: {
    day: 'Saturday',
    startTime: '02:00',
    endTime: '06:00',
    timezone: 'EST',
    durationMinutes: 240
  },
  maxConcurrentPatches: 2,
  devopsTeamSize: 3,
  regulatory: ['PCI-DSS'],
  slaRequirements: {
    'payment-api': 99.99,
    'customer-portal': 99.9,
    'internal-dashboard': 99.5,
    'auth-service': 99.99,
    'database-layer': 99.99
  }
}

/**
 * Load the complete Meridian scenario.
 */
export function loadMeridianScenario() {
  return {
    company: {
      name: 'Meridian Financial Services',
      type: 'Mid-sized fintech, cloud-native',
      employees: 500,
      clients: 'B2B financial services for regional banks and credit unions'
    },
    services: MERIDIAN_SERVICES.map(s => ({ ...s })), // deep copy
    dependencies: MERIDIAN_DEPENDENCIES.map(d => ({ ...d })),
    vulnerabilities: MERIDIAN_VULNERABILITIES.map(v => ({
      ...v,
      constraints: v.constraints.map(c => ({ ...c }))
    })),
    constraints: MERIDIAN_CONSTRAINTS
  }
}
