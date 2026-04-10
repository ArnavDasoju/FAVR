import numpy as np
from typing import Dict, List, Tuple


class BayesianRiskGraph:
    """
    Models infrastructure as a Bayesian network where vulnerability risk
    propagates through service dependencies.
    """

    def __init__(self, services: List[dict], dependencies: List[dict], cves: List[dict]):
        self.services = {s["name"]: s for s in services}
        self.dependencies = dependencies
        self.cves = cves
        self.prior_risk: Dict[str, float] = {}
        self.propagation_prob: Dict[Tuple[str, str], float] = {}
        self.posterior_risk: Dict[str, float] = {}

    def compute_prior_risk(self) -> Dict[str, float]:
        """
        Compute prior risk for each service based on its own CVEs.
        Uses: 1 - product(1 - cvss/10) for each CVE affecting the service.
        """
        for name in self.services:
            service_cves = [c for c in self.cves if c["affected_service"] == name]
            if not service_cves:
                self.prior_risk[name] = 0.0
            else:
                p_none = 1.0
                for cve in service_cves:
                    p_exploit = cve["cvss_score"] / 10.0
                    if cve.get("exploit_available", False):
                        p_exploit = min(p_exploit * 1.3, 1.0)
                    p_none *= (1.0 - p_exploit)
                self.prior_risk[name] = 1.0 - p_none
        return self.prior_risk

    def compute_propagation_probabilities(self) -> Dict[Tuple[str, str], float]:
        """
        Compute propagation probability for each dependency edge.
        """
        PROPAGATION_WEIGHTS = {
            "hard": 0.8,
            "soft": 0.4,
            "shared": 0.6,
        }
        for dep in self.dependencies:
            parent = dep["from"]
            child = dep["to"]
            dep_type = dep.get("type", "hard")
            self.propagation_prob[(parent, child)] = PROPAGATION_WEIGHTS.get(dep_type, 0.5)
        return self.propagation_prob

    def propagate_risk(self) -> Dict[str, float]:
        """
        Propagate risk through the dependency graph using topological ordering.
        P(node) = P(own) + (1 - P(own)) * [1 - product(1 - P(parent) * P(edge))]
        """
        self.compute_prior_risk()
        self.compute_propagation_probabilities()

        order = self._topological_sort()
        self.posterior_risk = dict(self.prior_risk)

        for node in order:
            parents = [(d["from"], d["to"]) for d in self.dependencies if d["to"] == node]
            if not parents:
                continue

            p_no_propagation = 1.0
            for parent_name, _ in parents:
                parent_risk = self.posterior_risk.get(parent_name, 0.0)
                edge_prob = self.propagation_prob.get((parent_name, node), 0.5)
                p_no_propagation *= (1.0 - parent_risk * edge_prob)

            p_inherited = 1.0 - p_no_propagation
            own_risk = self.prior_risk.get(node, 0.0)
            self.posterior_risk[node] = own_risk + (1.0 - own_risk) * p_inherited

        return self.posterior_risk

    def get_cve_propagated_scores(self) -> List[dict]:
        """
        Return CVEs with updated risk scores that incorporate propagated risk.
        """
        self.propagate_risk()
        scored_cves = []
        for cve in self.cves:
            service = cve["affected_service"]
            propagated = self.posterior_risk.get(service, 0.0)
            prior = self.prior_risk.get(service, 0.0)
            risk_multiplier = propagated / max(prior, 0.01)

            scored_cves.append({
                **cve,
                "prior_service_risk": round(prior, 4),
                "propagated_service_risk": round(propagated, 4),
                "risk_multiplier": round(risk_multiplier, 4),
                "effective_score": round(cve["cvss_score"] * min(risk_multiplier, 1.5), 2),
            })
        return scored_cves

    def _topological_sort(self) -> List[str]:
        """Kahn's algorithm for topological ordering."""
        in_degree = {name: 0 for name in self.services}
        adj: Dict[str, List[str]] = {name: [] for name in self.services}
        for dep in self.dependencies:
            adj[dep["from"]].append(dep["to"])
            in_degree[dep["to"]] = in_degree.get(dep["to"], 0) + 1

        queue = [n for n in in_degree if in_degree[n] == 0]
        order = []
        while queue:
            node = queue.pop(0)
            order.append(node)
            for child in adj.get(node, []):
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        return order
