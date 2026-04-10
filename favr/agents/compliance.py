from .base import Agent


class ComplianceAgent(Agent):
    """Checks if proposed patches affect regulatory compliance requirements."""

    name = "compliance_agent"
    description = "Evaluates patch plans against PCI-DSS and other compliance frameworks"

    def process(self, input_data: dict) -> dict:
        """
        Input: remediation_plans, constraints (regulatory context), findings
        Output: compliance flags, required reviews, priority escalations
        """
        plans = input_data["remediation_plans"]
        constraints = input_data.get("constraints", {})
        regulatory = constraints.get("regulatory", {})
        pci_scope = regulatory.get("scope", [])

        self._log("Evaluating compliance impact of remediation plans...")

        flags = []
        escalations = []
        reviews_required = []

        for plan in plans:
            cve_id = plan["cve_id"]
            service = plan["service"]

            # Check PCI-DSS scope
            if service in pci_scope:
                flag = {
                    "cve_id": cve_id,
                    "service": service,
                    "framework": "PCI-DSS",
                    "flag_type": "pci_scope_change",
                    "description": f"Patch to {service} is in PCI-DSS scope. Requires additional review and documentation.",
                    "required_actions": [
                        "Document change in PCI change log",
                        "Obtain approval from two authorized reviewers",
                        "Update PCI evidence repository after deployment",
                        "Schedule post-patch PCI scan within 72 hours",
                    ],
                    "additional_review_hours": regulatory.get("review_time_hours", 2),
                }
                flags.append(flag)

                reviews_required.append({
                    "cve_id": cve_id,
                    "service": service,
                    "review_type": "PCI-DSS Change Review",
                    "reviewers_needed": 2,
                    "estimated_hours": regulatory.get("review_time_hours", 2),
                })

                self._log(f"PCI-DSS flag: {cve_id} in {service} requires additional review")

            # Check if critical/high CVEs in PCI scope should be escalated
            if plan["severity"] in ("CRITICAL", "HIGH") and service in pci_scope:
                escalation = {
                    "cve_id": cve_id,
                    "service": service,
                    "reason": f"Critical/High severity vulnerability in PCI-scoped service {service}",
                    "recommended_priority": "immediate",
                    "regulatory_deadline": regulatory.get("audit_deadline"),
                }
                escalations.append(escalation)

                self.send_message(
                    "orchestrator",
                    "ESCALATE",
                    {
                        "cve_id": cve_id,
                        "reason": f"{plan['severity']} vulnerability in PCI-scoped {service} — regulatory deadline {regulatory.get('audit_deadline', 'TBD')}",
                        "recommended_action": "Prioritize this patch in the next maintenance window",
                        "compliance_framework": "PCI-DSS",
                    },
                    priority="critical",
                )

            # Check for change freeze conflicts
            change_freeze = constraints.get("change_management", {}).get("change_freeze_dates", [])
            if change_freeze:
                flag_freeze = {
                    "cve_id": cve_id,
                    "flag_type": "change_freeze_warning",
                    "description": f"Change freeze dates approaching: {', '.join(change_freeze)}. Ensure patch is deployed before freeze.",
                    "freeze_dates": change_freeze,
                }
                flags.append(flag_freeze)

        # Summary
        total_additional_hours = sum(r["estimated_hours"] for r in reviews_required)
        self._log(
            f"Compliance review complete: {len(flags)} flags, "
            f"{len(escalations)} escalations, "
            f"{total_additional_hours}h additional review time needed"
        )

        self.send_message(
            "orchestrator",
            "INFORM",
            {
                "summary": f"Compliance review: {len(escalations)} patches escalated for regulatory priority",
                "total_flags": len(flags),
                "escalations": len(escalations),
                "additional_review_hours": total_additional_hours,
                "pci_affected_patches": len([f for f in flags if f.get("framework") == "PCI-DSS"]),
            },
        )

        return {
            "compliance_flags": flags,
            "escalations": escalations,
            "reviews_required": reviews_required,
            "total_additional_review_hours": total_additional_hours,
        }
