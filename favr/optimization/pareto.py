import numpy as np
from typing import List, Dict


class ParetoOptimizer:
    """
    Multi-objective optimization across competing priorities.
    Produces a Pareto front of non-dominated patching orderings.
    """

    OBJECTIVES = ["risk", "downtime", "cost", "compliance_gap"]

    def __init__(self, scored_cves: List[dict], constraints: dict):
        self.cves = scored_cves
        self.constraints = constraints

    def evaluate_ordering(self, ordering: List[str]) -> Dict[str, float]:
        cve_map = {c["cve_id"]: c for c in self.cves}

        # Objective 1: Cumulative risk exposure
        total_risk = sum(c["effective_score"] for c in self.cves)
        running = total_risk
        risk_area = 0
        for cve_id in ordering:
            risk_area += running
            running -= cve_map[cve_id]["effective_score"]

        # Objective 2: Total downtime
        total_downtime = 0
        for cve_id in ordering:
            cve = cve_map[cve_id]
            base_time = cve.get("estimated_patch_hours", 2)
            criticality = cve.get("service_criticality", 5)
            total_downtime += base_time * (1 + criticality / 20)

        # Objective 3: Cost
        total_cost = 0
        for cve_id in ordering:
            cve = cve_map[cve_id]
            complexity = cve.get("complexity_score", 5)
            total_cost += complexity * 500

        # Objective 4: Compliance gap
        compliance_gap = 0
        for position, cve_id in enumerate(ordering):
            cve = cve_map[cve_id]
            if cve.get("compliance_relevant", False):
                compliance_gap += position

        return {
            "risk": round(risk_area, 2),
            "downtime": round(total_downtime, 2),
            "cost": round(total_cost, 2),
            "compliance_gap": round(compliance_gap, 2),
        }

    def find_pareto_front(self, orderings: List[List[str]]) -> List[dict]:
        evaluated = []
        for ordering in orderings:
            scores = self.evaluate_ordering(ordering)
            evaluated.append({"ordering": ordering, "scores": scores})

        pareto_front = []
        for i, candidate in enumerate(evaluated):
            is_dominated = False
            for j, other in enumerate(evaluated):
                if i == j:
                    continue
                all_leq = all(
                    other["scores"][obj] <= candidate["scores"][obj]
                    for obj in self.OBJECTIVES
                )
                any_lt = any(
                    other["scores"][obj] < candidate["scores"][obj]
                    for obj in self.OBJECTIVES
                )
                if all_leq and any_lt:
                    is_dominated = True
                    break

            if not is_dominated:
                pareto_front.append(candidate)

        pareto_front.sort(key=lambda x: x["scores"]["risk"])
        return pareto_front

    def generate_tradeoff_profiles(self, pareto_front: List[dict]) -> List[dict]:
        if not pareto_front:
            return []

        profiles = []
        for item in pareto_front:
            scores = item["scores"]
            label = self._classify_profile(scores, pareto_front)
            profiles.append({
                "ordering": item["ordering"],
                "scores": scores,
                "label": label,
                "summary": self._generate_summary(label, scores),
            })

        return profiles

    def _classify_profile(self, scores: dict, front: List[dict]) -> str:
        best_obj = None
        best_rank = len(front) + 1

        for obj in self.OBJECTIVES:
            all_scores = sorted([f["scores"][obj] for f in front])
            try:
                rank = all_scores.index(scores[obj]) + 1
            except ValueError:
                rank = len(front)
            if rank < best_rank:
                best_rank = rank
                best_obj = obj

        labels = {
            "risk": "Maximum Security",
            "downtime": "Minimum Disruption",
            "cost": "Budget Optimized",
            "compliance_gap": "Compliance First",
        }
        return labels.get(best_obj, "Balanced")

    def _generate_summary(self, label: str, scores: dict) -> str:
        summaries = {
            "Maximum Security": (
                f"Patches highest-risk vulnerabilities first. "
                f"Risk exposure: {scores['risk']:.0f}, but requires "
                f"{scores['downtime']:.1f}hrs downtime."
            ),
            "Minimum Disruption": (
                f"Minimizes service disruption to "
                f"{scores['downtime']:.1f}hrs. Risk exposure: {scores['risk']:.0f}. "
                f"Best for teams with tight maintenance windows."
            ),
            "Budget Optimized": (
                f"Keeps remediation cost to ${scores['cost']:.0f}. "
                f"Risk exposure: {scores['risk']:.0f}. Best when engineering "
                f"bandwidth is limited."
            ),
            "Compliance First": (
                f"Prioritizes regulatory patches. Compliance gap "
                f"score: {scores['compliance_gap']:.0f}. Best when audit "
                f"deadlines are approaching."
            ),
        }
        return summaries.get(label, "Balanced approach across all objectives.")


def _generate_diverse_orderings(cves: List[dict], constraints: dict) -> List[List[str]]:
    """Generate diverse candidate orderings by varying objective weights."""
    orderings = []
    cve_ids = [c["cve_id"] for c in cves]
    cve_map = {c["cve_id"]: c for c in cves}

    weight_profiles = [
        {"risk": 1.0, "downtime": 0.0, "cost": 0.0, "compliance": 0.0},
        {"risk": 0.0, "downtime": 1.0, "cost": 0.0, "compliance": 0.0},
        {"risk": 0.0, "downtime": 0.0, "cost": 1.0, "compliance": 0.0},
        {"risk": 0.0, "downtime": 0.0, "cost": 0.0, "compliance": 1.0},
        {"risk": 0.4, "downtime": 0.2, "cost": 0.2, "compliance": 0.2},
        {"risk": 0.6, "downtime": 0.1, "cost": 0.1, "compliance": 0.2},
        {"risk": 0.3, "downtime": 0.4, "cost": 0.2, "compliance": 0.1},
        {"risk": 0.2, "downtime": 0.2, "cost": 0.4, "compliance": 0.2},
    ]

    for weights in weight_profiles:
        for _ in range(250):
            scored = []
            for cve_id in cve_ids:
                c = cve_map[cve_id]
                score = (
                    weights["risk"] * c["effective_score"]
                    + weights["downtime"] * (10 - c.get("estimated_patch_hours", 2))
                    + weights["cost"] * (10 - c.get("complexity_score", 5))
                    + weights["compliance"] * (10 if c.get("compliance_relevant") else 0)
                )
                noise = np.random.uniform(-0.2, 0.2) * abs(score) if score != 0 else 0
                scored.append((cve_id, score + noise))
            scored.sort(key=lambda x: x[1], reverse=True)
            orderings.append([cve_id for cve_id, _ in scored])

    return orderings


def run_full_optimization(services, dependencies, cves, constraints) -> dict:
    """
    Full pipeline: Bayesian -> Monte Carlo -> Pareto.
    Main entry point called by the pipeline orchestrator.
    """
    from .bayesian import BayesianRiskGraph
    from .monte_carlo import MonteCarloSimulator

    # Stage 1: Bayesian Risk Propagation
    graph = BayesianRiskGraph(services, dependencies, cves)
    propagated_cves = graph.get_cve_propagated_scores()

    # Stage 2: Monte Carlo Simulation
    simulator = MonteCarloSimulator(propagated_cves, constraints, n_iterations=2000)
    mc_results = simulator.simulate()

    # Stage 3: Pareto Optimization
    diverse_orderings = _generate_diverse_orderings(propagated_cves, constraints)
    pareto = ParetoOptimizer(propagated_cves, constraints)
    pareto_front = pareto.find_pareto_front(diverse_orderings)
    profiles = pareto.generate_tradeoff_profiles(pareto_front)

    return {
        "bayesian": {
            "prior_risks": graph.prior_risk,
            "posterior_risks": graph.posterior_risk,
            "propagated_cves": propagated_cves,
        },
        "monte_carlo": mc_results,
        "pareto": {
            "front_size": len(pareto_front),
            "profiles": profiles,
        },
    }
