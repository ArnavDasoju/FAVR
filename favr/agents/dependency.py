from .base import Agent


class DependencyConflictAgent(Agent):
    """Checks if patches conflict with each other or break downstream services."""

    name = "dependency_agent"
    description = "Detects dependency conflicts between patches and proposes resolution paths"

    def process(self, input_data: dict) -> dict:
        """
        Input: patch_plan (ordered CVEs), dependency_graph, scan_findings
        Output: conflict report with resolution suggestions
        """
        plan = input_data["patch_plan"]
        dependencies = input_data["dependencies"]
        findings = input_data.get("findings", [])

        self._log("Analyzing patch plan for dependency conflicts...")

        # Build dependency map
        dep_map = {}
        for dep in dependencies:
            dep_map.setdefault(dep["from"], []).append(dep)
            dep_map.setdefault(dep["to"], []).append(dep)

        conflicts = []
        resolutions = []

        # Check each finding for conflicts
        for finding in findings:
            conflict = finding.get("conflict_detected")
            if not conflict:
                continue

            cve_id = finding["cve_id"]
            self._log(f"CONFLICT: {cve_id} - {conflict['description']}")

            conflict_entry = {
                "cve_id": cve_id,
                "type": conflict["type"],
                "description": conflict["description"],
                "affected_services": conflict.get("affected_services", []),
                "severity": "high",
            }
            conflicts.append(conflict_entry)

            # Generate resolution
            resolution = {
                "conflict_id": cve_id,
                "strategy": "coordinated_upgrade",
                "steps": [
                    f"1. Notify teams owning {', '.join(conflict.get('affected_services', []))}",
                    f"2. Stage patches in test environment for both services simultaneously",
                    f"3. Run integration tests across affected service boundaries",
                    f"4. Deploy coordinated patch during maintenance window",
                ],
                "options": conflict.get("resolution_options", []),
                "estimated_additional_time_hours": 2,
                "risk_level": "medium",
            }
            resolutions.append(resolution)

            # Send BLOCK message
            self.send_message(
                "remediation_agent",
                "BLOCK",
                {
                    "blocking_cve": cve_id,
                    "reason": conflict["description"],
                    "suggestion": resolution["options"][0] if resolution["options"] else "Coordinate patch across services",
                    "affected_services": conflict.get("affected_services", []),
                },
                priority="critical",
            )

        # Check ordering conflicts - can't patch dependent before dependency
        ordering_issues = []
        for i, cve_id in enumerate(plan):
            finding = next((f for f in findings if f["cve_id"] == cve_id), None)
            if not finding:
                continue
            service = finding["service"]
            # Check if any service this depends on has patches later in the plan
            for dep in dependencies:
                if dep["to"] == service and dep["type"] == "hard":
                    parent = dep["from"]
                    parent_patches = [
                        (j, f["cve_id"]) for j, pid in enumerate(plan)
                        for f in findings
                        if f["cve_id"] == pid and f["service"] == parent and j > i
                    ]
                    for j, parent_cve in parent_patches:
                        issue = {
                            "type": "ordering_conflict",
                            "description": f"{cve_id} (position {i+1}) patches {service} before "
                                         f"{parent_cve} (position {j+1}) patches {parent}, "
                                         f"but {service} depends on {parent}",
                            "suggestion": f"Consider patching {parent_cve} before {cve_id}",
                        }
                        ordering_issues.append(issue)

        if ordering_issues:
            self._log(f"Found {len(ordering_issues)} ordering issues")
            self.send_message(
                "orchestrator",
                "INFORM",
                {
                    "summary": f"Found {len(ordering_issues)} ordering recommendations",
                    "reason": "Some patches may benefit from reordering based on service dependencies",
                    "issues": ordering_issues,
                },
                priority="normal",
            )

        # Summary
        self._log(f"Analysis complete: {len(conflicts)} conflicts, {len(ordering_issues)} ordering issues")

        self.send_message(
            "orchestrator",
            "INFORM",
            {
                "summary": f"Dependency analysis complete: {len(conflicts)} conflicts found",
                "conflicts_count": len(conflicts),
                "resolutions_count": len(resolutions),
                "ordering_issues": len(ordering_issues),
            },
        )

        return {
            "conflicts": conflicts,
            "resolutions": resolutions,
            "ordering_issues": ordering_issues,
        }
