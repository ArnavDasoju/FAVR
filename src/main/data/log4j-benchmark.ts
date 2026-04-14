/**
 * Log4j Benchmark Scenario — validates FAVR's priority ordering against
 * a well-studied real-world vulnerability landscape.
 *
 * This scenario models a Java microservices application affected by
 * Log4Shell (CVE-2021-44228) alongside other real CVEs with varying
 * CVSS scores and EPSS probabilities.
 *
 * EXPECTED RESULT:
 * FAVR should prioritize Log4Shell first (CVSS 10.0, EPSS 0.975, in KEV,
 * active exploitation), but the key differentiator is what comes NEXT.
 *
 * A naive CVSS-sort would put Spring4Shell (CVE-2022-22965, CVSS 9.8)
 * second, but FAVR should recognize that CVE-2021-45046 (Log4j follow-up,
 * EPSS 0.92) or the actively exploited Spring Cloud Gateway SSRF
 * (EPSS 0.87) represent higher REAL risk than Spring4Shell (EPSS 0.12).
 *
 * EXPECTED PRIORITY ORDER (FAVR, risk-optimized):
 * 1. CVE-2021-44228 (Log4Shell) — CVSS 10.0, EPSS 0.975, KEV, remote
 * 2. CVE-2021-45046 (Log4j DoS/RCE) — CVSS 9.0, EPSS 0.92, KEV
 * 3. CVE-2022-22947 (Spring Cloud Gateway SSRF) — CVSS 10.0, EPSS 0.87, KEV
 * 4. CVE-2022-22965 (Spring4Shell) — CVSS 9.8, EPSS 0.12 (low exploitation!)
 * 5. CVE-2023-20873 (Actuator bypass) — CVSS 9.8, EPSS 0.08
 *
 * NAIVE (CVSS-sort) would put Spring4Shell at #2 — wrong! Its EPSS is
 * only 0.12 despite CVSS 9.8. FAVR should catch this divergence.
 *
 * Source: CISA KEV catalog, FIRST.org EPSS data, NVD
 */

import type { Service, Dependency, Vulnerability } from '../engine/types'

export const LOG4J_SERVICES: Service[] = [
  {
    id: 'api-gateway',
    name: 'API Gateway',
    techStack: ['Java 11', 'Spring Cloud Gateway 3.1.0', 'Netty 4.1.72'],
    tier: 'critical',
    sla: 99.99,
    description: 'Edge gateway routing all external traffic. Single point of entry.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['PCI-DSS', 'SOC2'],
    maintenanceWindow: { day: 'Saturday', startTime: '02:00', endTime: '06:00', timezone: 'UTC', durationMinutes: 240 }
  },
  {
    id: 'order-service',
    name: 'Order Service',
    techStack: ['Java 17', 'Spring Boot 2.7.0', 'Log4j 2.14.1', 'PostgreSQL 14'],
    tier: 'critical',
    sla: 99.95,
    description: 'Core order processing. Uses Log4j for structured logging.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['PCI-DSS'],
    maintenanceWindow: { day: 'Saturday', startTime: '02:00', endTime: '06:00', timezone: 'UTC', durationMinutes: 240 }
  },
  {
    id: 'user-service',
    name: 'User Service',
    techStack: ['Java 11', 'Spring Boot 2.6.3', 'Log4j 2.14.1', 'Redis 6.2'],
    tier: 'high',
    sla: 99.9,
    description: 'Authentication and user management. Also uses vulnerable Log4j.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['GDPR', 'SOC2'],
    maintenanceWindow: { day: 'Sunday', startTime: '00:00', endTime: '06:00', timezone: 'UTC', durationMinutes: 360 }
  },
  {
    id: 'notification-service',
    name: 'Notification Service',
    techStack: ['Java 17', 'Spring Boot 3.0.0', 'Kafka 3.3.0'],
    tier: 'medium',
    sla: 99.5,
    description: 'Sends emails and push notifications. Lower tier, modern Spring Boot.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: [],
    maintenanceWindow: { day: 'Wednesday', startTime: '22:00', endTime: '02:00', timezone: 'UTC', durationMinutes: 240 }
  },
  {
    id: 'database',
    name: 'PostgreSQL Cluster',
    techStack: ['PostgreSQL 14.5', 'pgBouncer 1.17'],
    tier: 'critical',
    sla: 99.99,
    description: 'Primary data store for all services.',
    baseCompromiseProbability: 0,
    currentRiskScore: 0,
    complianceFrameworks: ['PCI-DSS', 'GDPR'],
    maintenanceWindow: { day: 'Saturday', startTime: '03:00', endTime: '05:00', timezone: 'UTC', durationMinutes: 120 }
  }
]

export const LOG4J_DEPENDENCIES: Dependency[] = [
  { from: 'api-gateway', to: 'order-service', type: 'api', propagationWeight: 0.85, description: 'Routes order API traffic' },
  { from: 'api-gateway', to: 'user-service', type: 'auth', propagationWeight: 0.9, description: 'Auth validation on every request' },
  { from: 'order-service', to: 'database', type: 'data', propagationWeight: 0.9, description: 'Reads/writes order data' },
  { from: 'order-service', to: 'user-service', type: 'api', propagationWeight: 0.6, description: 'Validates user permissions' },
  { from: 'order-service', to: 'notification-service', type: 'api', propagationWeight: 0.3, description: 'Triggers order confirmations' },
  { from: 'user-service', to: 'database', type: 'data', propagationWeight: 0.85, description: 'Stores user profiles' },
]

export const LOG4J_VULNERABILITIES: Vulnerability[] = [
  // ── THE STAR: Log4Shell ────────────────────────────────────
  {
    id: 'bench-001',
    cveId: 'CVE-2021-44228',
    title: 'Apache Log4j2 Remote Code Execution (Log4Shell)',
    description: 'Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker-controlled LDAP/RMI. Allows RCE via crafted log messages. Actively exploited in the wild since Dec 2021.',
    severity: 'critical',
    cvssScore: 10.0,
    epssScore: 0.975,
    exploitProbability: 0.95,
    affectedServiceIds: ['order-service', 'user-service'],
    affectedPackage: 'log4j-core@2.14.1',
    patchedVersion: 'log4j-core@2.17.1',
    remediationCost: 4,
    remediationDowntime: 30,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'compliance', description: 'CISA Emergency Directive 22-02 mandates immediate remediation' }
    ],
    knownExploit: true,
    inKev: true,
    attackVector: 'network',
    hasPublicExploit: true,
    complianceViolations: ['PCI-DSS'],
    complianceDeadlineDays: 0
  },

  // ── Log4j follow-up (EPSS 0.92, often deprioritized by CVSS-only) ──
  {
    id: 'bench-002',
    cveId: 'CVE-2021-45046',
    title: 'Apache Log4j2 Thread Context DoS/RCE',
    description: 'Incomplete fix for CVE-2021-44228. Certain non-default configs still allow RCE via Thread Context Map patterns.',
    severity: 'critical',
    cvssScore: 9.0,
    epssScore: 0.92,
    exploitProbability: 0.85,
    affectedServiceIds: ['order-service', 'user-service'],
    affectedPackage: 'log4j-core@2.15.0',
    patchedVersion: 'log4j-core@2.17.1',
    remediationCost: 2,
    remediationDowntime: 15,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'dependency', description: 'Must be patched alongside CVE-2021-44228', blockedBy: [] }
    ],
    knownExploit: true,
    inKev: true,
    attackVector: 'network',
    hasPublicExploit: true,
    complianceViolations: ['PCI-DSS'],
    complianceDeadlineDays: 0
  },

  // ── Spring Cloud Gateway RCE (EPSS 0.87, in KEV) ──────────
  {
    id: 'bench-003',
    cveId: 'CVE-2022-22947',
    title: 'Spring Cloud Gateway Code Injection via SpEL',
    description: 'Spring Cloud Gateway before 3.1.1 allows code injection via SpEL expressions in Actuator gateway routes. Actively exploited.',
    severity: 'critical',
    cvssScore: 10.0,
    epssScore: 0.87,
    exploitProbability: 0.8,
    affectedServiceIds: ['api-gateway'],
    affectedPackage: 'spring-cloud-gateway@3.1.0',
    patchedVersion: 'spring-cloud-gateway@3.1.1',
    remediationCost: 3,
    remediationDowntime: 20,
    complexity: 'medium',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: true,
    inKev: true,
    attackVector: 'network',
    hasPublicExploit: true,
    complianceViolations: ['PCI-DSS', 'SOC2'],
    complianceDeadlineDays: 7
  },

  // ── THE TRAP: Spring4Shell (CVSS 9.8 but EPSS only 0.12!) ──
  // A naive CVSS-sort puts this at #2. FAVR should push it lower.
  {
    id: 'bench-004',
    cveId: 'CVE-2022-22965',
    title: 'Spring Framework RCE (Spring4Shell)',
    description: 'Class injection via data binding in Spring Framework. Despite media attention, real-world exploitation is limited (specific JDK9+ and WAR deployment required).',
    severity: 'critical',
    cvssScore: 9.8,
    epssScore: 0.12,
    exploitProbability: 0.3,
    affectedServiceIds: ['order-service'],
    affectedPackage: 'spring-webmvc@5.3.18',
    patchedVersion: 'spring-webmvc@5.3.20',
    remediationCost: 4,
    remediationDowntime: 25,
    complexity: 'high',
    status: 'open',
    patchOrder: null,
    constraints: [
      { type: 'dependency', description: 'Spring Framework upgrade requires regression testing all endpoints' }
    ],
    knownExploit: true,
    inKev: true,
    attackVector: 'network',
    hasPublicExploit: true,
    complianceViolations: [],
    complianceDeadlineDays: 14
  },

  // ── Actuator Bypass (CVSS 9.8 but EPSS 0.08) ──────────────
  {
    id: 'bench-005',
    cveId: 'CVE-2023-20873',
    title: 'Spring Boot Actuator Security Bypass',
    description: 'Spring Boot Actuator endpoints accessible without authentication when deployed to Cloud Foundry. Very specific conditions.',
    severity: 'critical',
    cvssScore: 9.8,
    epssScore: 0.08,
    exploitProbability: 0.15,
    affectedServiceIds: ['order-service', 'notification-service'],
    affectedPackage: 'spring-boot-actuator@2.7.0',
    patchedVersion: 'spring-boot-actuator@2.7.11',
    remediationCost: 2,
    remediationDowntime: 10,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    inKev: false,
    attackVector: 'network',
    hasPublicExploit: false,
    complianceViolations: ['SOC2'],
    complianceDeadlineDays: 30
  },

  // ── Medium-severity but high-EPSS (interesting divergence) ──
  {
    id: 'bench-006',
    cveId: 'CVE-2022-42889',
    title: 'Apache Commons Text RCE (Text4Shell)',
    description: 'Arbitrary code execution via StringSubstitutor interpolation. Compared to Log4Shell but less impactful due to fewer deployments.',
    severity: 'high',
    cvssScore: 9.8,
    epssScore: 0.52,
    exploitProbability: 0.45,
    affectedServiceIds: ['notification-service'],
    affectedPackage: 'commons-text@1.9',
    patchedVersion: 'commons-text@1.10.0',
    remediationCost: 1,
    remediationDowntime: 5,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: true,
    inKev: false,
    attackVector: 'network',
    hasPublicExploit: true,
    complianceViolations: [],
    complianceDeadlineDays: null
  },

  // ── Low CVSS but non-zero EPSS (shouldn't be first) ────────
  {
    id: 'bench-007',
    cveId: 'CVE-2022-25857',
    title: 'SnakeYAML DoS via Recursive Objects',
    description: 'SnakeYAML before 1.32 allows DoS via deeply nested objects. Not code execution but affects availability.',
    severity: 'medium',
    cvssScore: 7.5,
    epssScore: 0.18,
    exploitProbability: 0.25,
    affectedServiceIds: ['order-service'],
    affectedPackage: 'snakeyaml@1.30',
    patchedVersion: 'snakeyaml@1.32',
    remediationCost: 1,
    remediationDowntime: 5,
    complexity: 'low',
    status: 'open',
    patchOrder: null,
    constraints: [],
    knownExploit: false,
    inKev: false,
    attackVector: 'network',
    hasPublicExploit: true,
    complianceViolations: [],
    complianceDeadlineDays: null
  }
]

/**
 * Benchmark Validation Notes:
 *
 * After running FAVR analysis on this scenario, verify:
 *
 * 1. Log4Shell (bench-001) should be #1 in optimal order
 *    - Highest EPSS (0.975), in KEV, affects 2 critical services
 *
 * 2. Spring4Shell (bench-004) should NOT be #2 despite CVSS 9.8
 *    - Its EPSS (0.12) is much lower than bench-002 (0.92) and bench-003 (0.87)
 *    - FAVR's EPSS-driven model should catch this divergence
 *
 * 3. The EPSS-vs-CVSS divergence on bench-004 and bench-005 should be
 *    highlighted in the dashboard as "CVSS says critical, EPSS says unlikely"
 *
 * 4. Risk reduction curve should show a steep initial drop (patching
 *    bench-001 removes risk from 2 services) then diminishing returns
 *
 * 5. Compare FAVR's order vs naive CVSS sort:
 *    - NAIVE:  001, 003, 004, 005, 006, 002, 007
 *    - FAVR:   001, 002, 003, 006, 004, 007, 005 (approximately)
 *    The key difference: 002 (EPSS 0.92) jumps ahead of 004 (EPSS 0.12)
 */
