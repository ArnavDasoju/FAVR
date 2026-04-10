from .base import Agent


class RiskAssessmentAgent(Agent):
    """Re-evaluates risk after proposed patches are applied."""

    name = "risk_agent"
    description = "Calculates residual risk at each step of the remediation plan"

    def process(self, input_data: dict) -> dict:
        """
        Input: optimization_results (bayesian + monte carlo), remediation_plans, patch_order
        Output: risk scores at each step, before/after comparison
        """
        opt_results = input_data["optimization_results"]
        plans = input_data["remediation_plans"]
        bayesian = opt_results["bayesian"]
        mc = opt_results["monte_carlo"]

        self._log("Calculating residual risk at each patching step...")

        propagated_cves = bayesian["propagated_cves"]
        cve_map = {c["cve_id"]: c for c in propagated_cves}
        plan_map = {p["cve_id"]: p for p in plans}

        total_risk_before = sum(c["effective_score"] for c in propagated_cves)
        total_cvss_before = sum(c["cvss_score"] for c in propagated_cves)

        # Calculate risk at each step of optimal ordering
        optimal_order = mc["optimal_order"]
        risk_steps = []
        running_risk = total_risk_before
        running_cvss = total_cvss_before
        patched_count = 0

        for i, cve_id in enumerate(optimal_order):
            cve = cve_map.get(cve_id, {})
            plan = plan_map.get(cve_id, {})

            running_risk -= cve.get("effective_score", 0)
            running_cvss -= cve.get("cvss_score", 0)
            patched_count += 1

            pct_reduction = (1 - running_risk / total_risk_before) * 100 if total_risk_before > 0 else 0

            step = {
                "position": i + 1,
                "cve_id": cve_id,
                "severity": cve.get("severity", "UNKNOWN"),
                "service": cve.get("affected_service", ""),
                "risk_removed": round(cve.get("effective_score", 0), 2),
                "residual_risk": round(running_risk, 2),
                "residual_cvss": round(running_cvss, 2),
                "cumulative_reduction_pct": round(pct_reduction, 1),
                "estimated_hours": plan.get("estimated_hours", 2),
            }
            risk_steps.append(step)

            if i < 5:
                self._log(
                    f"Step {i+1}: Patch {cve_id} ({cve.get('severity', '?')}) -> "
                    f"risk drops to {running_risk:.1f} ({pct_reduction:.0f}% reduced)"
                )

        # Before/after summary
        summary = {
            "total_risk_before": round(total_risk_before, 2),
            "total_risk_after": 0,
            "total_cvss_before": round(total_cvss_before, 2),
            "total_cvss_after": 0,
            "risk_reduction_pct": 100.0,
            "total_vulnerabilities": len(propagated_cves),
            "critical_count": len([c for c in propagated_cves if c.get("severity") == "CRITICAL"]),
            "high_count": len([c for c in propagated_cves if c.get("severity") == "HIGH"]),
            "medium_count": len([c for c in propagated_cves if c.get("severity") == "MEDIUM"]),
            "low_count": len([c for c in propagated_cves if c.get("severity") == "LOW"]),
            "monte_carlo_improvement": mc.get("improvement_pct", 0),
        }

        # Risk at key milestones
        milestones = {}
        for pct in [25, 50, 75, 90]:
            for step in risk_steps:
                if step["cumulative_reduction_pct"] >= pct:
                    milestones[f"{pct}pct_reduction_at_step"] = step["position"]
                    milestones[f"{pct}pct_reduction_cve"] = step["cve_id"]
                    break

        self._log(
            f"Risk assessment complete: {total_risk_before:.1f} -> 0 "
            f"({len(propagated_cves)} patches, MC improvement: {mc.get('improvement_pct', 0)}%)"
        )

        self.send_message(
            "orchestrator",
            "INFORM",
            {
                "summary": f"Full remediation reduces risk from {total_risk_before:.0f} to 0. "
                          f"First 5 patches eliminate {risk_steps[4]['cumulative_reduction_pct'] if len(risk_steps) >= 5 else 'N/A'}% of risk.",
                "total_risk_before": summary["total_risk_before"],
                "monte_carlo_improvement": summary["monte_carlo_improvement"],
                "milestones": milestones,
            },
        )

        return {
            "risk_steps": risk_steps,
            "summary": summary,
            "milestones": milestones,
        }
