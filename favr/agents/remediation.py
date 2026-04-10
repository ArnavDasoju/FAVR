from .base import Agent


class RemediationPlanAgent(Agent):
    """Generates step-by-step remediation plans for each vulnerability."""

    name = "remediation_agent"
    description = "Generates detailed remediation plans with rollback procedures"

    def __init__(self, name=None, use_llm=False, api_key=None):
        super().__init__(name)
        self.use_llm = use_llm
        self.api_key = api_key
        self.blocked_cves = set()

    def receive_message(self, message):
        super().receive_message(message)
        if message.msg_type == "BLOCK":
            cve_id = message.payload.get("blocking_cve")
            if cve_id:
                self.blocked_cves.add(cve_id)
                self._log(f"CVE {cve_id} blocked by {message.from_agent}: {message.payload.get('reason', '')[:80]}")

    def process(self, input_data: dict) -> dict:
        """
        Input: findings (scan results), conflict_report, constraints
        Output: remediation plans per CVE
        """
        findings = input_data["findings"]
        conflict_report = input_data.get("conflict_report", {})
        constraints = input_data.get("constraints", {})
        resolutions = {r["conflict_id"]: r for r in conflict_report.get("resolutions", [])}

        self._log("Generating remediation plans...")
        plans = []

        for finding in findings:
            cve_id = finding["cve_id"]
            is_blocked = cve_id in self.blocked_cves
            resolution = resolutions.get(cve_id)

            plan = self._generate_plan(finding, is_blocked, resolution, constraints)
            plans.append(plan)

            status = "BLOCKED - requires conflict resolution" if is_blocked else "ready"
            self._log(f"Plan for {cve_id} ({finding['severity']}): {status}")

        # If there are blocked CVEs, send resolve messages with workaround
        for cve_id in self.blocked_cves:
            resolution = resolutions.get(cve_id)
            if resolution:
                self.send_message(
                    "orchestrator",
                    "RESOLVE",
                    {
                        "resolved_cve": cve_id,
                        "resolution_strategy": resolution["strategy"],
                        "steps": resolution["steps"],
                        "reason": f"Conflict for {cve_id} resolved via {resolution['strategy']}",
                    },
                    priority="high",
                )

        self.send_message(
            "orchestrator",
            "INFORM",
            {
                "summary": f"Generated {len(plans)} remediation plans ({len(self.blocked_cves)} with conflict resolutions)",
                "total_plans": len(plans),
                "blocked_count": len(self.blocked_cves),
                "total_estimated_hours": sum(p["estimated_hours"] for p in plans),
            },
        )

        return {"remediation_plans": plans}

    def _generate_plan(self, finding: dict, is_blocked: bool, resolution: dict | None, constraints: dict) -> dict:
        cve_id = finding["cve_id"]
        packages = finding.get("packages", [])
        pkg = packages[0] if packages else {}

        # Build remediation steps based on type
        steps = []
        if finding.get("conflict_detected") and resolution:
            steps.append({
                "action": "Resolve dependency conflict",
                "detail": resolution.get("steps", ["Coordinate with affected service teams"])[0] if resolution.get("steps") else "Coordinate upgrade",
                "estimated_minutes": 30,
            })

        steps.extend([
            {
                "action": "Create backup and snapshot",
                "detail": f"Snapshot {finding['service']} service state and database (if applicable)",
                "estimated_minutes": 15,
            },
            {
                "action": "Update dependency",
                "detail": f"Upgrade {pkg.get('name', 'package')} from {pkg.get('current', '?')} to {pkg.get('patched', 'latest')}",
                "estimated_minutes": 10,
            },
            {
                "action": "Run unit tests",
                "detail": f"Execute test suite for {finding['service']}",
                "estimated_minutes": 20,
            },
            {
                "action": "Run integration tests",
                "detail": "Verify service-to-service communication after patch",
                "estimated_minutes": 30,
            },
            {
                "action": "Deploy to staging",
                "detail": "Deploy patched version to staging environment and verify",
                "estimated_minutes": 15,
            },
            {
                "action": "Deploy to production",
                "detail": f"Rolling deploy to {finding['service']} during maintenance window",
                "estimated_minutes": 20,
            },
            {
                "action": "Post-deploy verification",
                "detail": "Monitor error rates, latency, and functionality for 30 minutes",
                "estimated_minutes": 30,
            },
        ])

        total_minutes = sum(s["estimated_minutes"] for s in steps)
        estimated_hours = round(total_minutes / 60, 1)

        rollback = {
            "trigger": "Error rate exceeds 1% or latency exceeds 2x baseline within 30 minutes of deploy",
            "steps": [
                f"Revert {finding['service']} to previous version via blue-green switch",
                "Restore database snapshot if schema changes were made",
                "Notify on-call team and create incident ticket",
                "Schedule retry for next maintenance window",
            ],
            "estimated_rollback_minutes": 15,
        }

        testing = {
            "unit_tests": f"{finding['service']}/tests/",
            "integration_tests": "Run full service mesh integration suite",
            "smoke_tests": [
                f"Verify {finding['service']} health endpoint returns 200",
                "Verify authentication flow works end-to-end",
                "Verify core business operations (transactions, logins, queries)",
            ],
        }

        return {
            "cve_id": cve_id,
            "service": finding["service"],
            "severity": finding["severity"],
            "is_blocked": is_blocked,
            "conflict_resolution": resolution["strategy"] if resolution else None,
            "steps": steps,
            "estimated_hours": estimated_hours,
            "rollback_procedure": rollback,
            "testing_requirements": testing,
            "requires_pci_review": finding.get("pci_scope", False),
            "files_to_modify": finding.get("files_affected", []),
            "packages_to_update": finding.get("packages", []),
        }
