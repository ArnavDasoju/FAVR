import numpy as np
from typing import List, Dict, Tuple
from collections import defaultdict


class MonteCarloSimulator:
    """
    Simulates thousands of patching orderings to find optimal sequences
    that minimize cumulative risk exposure over time.
    """

    def __init__(
        self,
        scored_cves: List[dict],
        constraints: dict,
        n_iterations: int = 2000,
        noise_pct: float = 0.20,
    ):
        self.cves = scored_cves
        self.constraints = constraints
        self.n_iterations = n_iterations
        self.noise_pct = noise_pct

    def simulate(self) -> dict:
        """
        Run Monte Carlo simulation. Returns optimal ordering,
        confidence intervals, and risk curve data.
        """
        all_orderings = []
        all_scores = []

        for _ in range(self.n_iterations):
            noisy_scores = []
            for cve in self.cves:
                base = cve["effective_score"]
                noise = np.random.uniform(-self.noise_pct, self.noise_pct)
                noisy = base * (1 + noise)
                noisy_scores.append((cve["cve_id"], noisy))

            noisy_scores.sort(key=lambda x: x[1], reverse=True)
            ordering = [cve_id for cve_id, _ in noisy_scores]

            cumulative_risk = self._compute_cumulative_risk(ordering)
            total_area = sum(cumulative_risk)

            all_orderings.append(ordering)
            all_scores.append(total_area)

        scored = list(zip(all_scores, all_orderings))
        scored.sort(key=lambda x: x[0])

        best_score, best_ordering = scored[0]
        top_5_pct = scored[:max(1, self.n_iterations // 20)]

        confidence = self._compute_position_confidence(top_5_pct)

        best_curve = self._compute_cumulative_risk(best_ordering)
        naive_ordering = sorted(
            [c["cve_id"] for c in self.cves],
            key=lambda cid: next(c["cvss_score"] for c in self.cves if c["cve_id"] == cid),
            reverse=True,
        )
        naive_curve = self._compute_cumulative_risk(naive_ordering)

        naive_area = sum(naive_curve)
        improvement_pct = round((naive_area - best_score) / naive_area * 100, 1) if naive_area > 0 else 0

        return {
            "optimal_order": best_ordering,
            "optimal_score": round(best_score, 2),
            "naive_score": round(naive_area, 2),
            "improvement_pct": improvement_pct,
            "risk_curve": [
                {"step": i, "risk": round(r, 4)} for i, r in enumerate(best_curve)
            ],
            "naive_curve": [
                {"step": i, "risk": round(r, 4)} for i, r in enumerate(naive_curve)
            ],
            "confidence_intervals": confidence,
            "iterations_run": self.n_iterations,
        }

    def _compute_cumulative_risk(self, ordering: List[str]) -> List[float]:
        cve_map = {c["cve_id"]: c for c in self.cves}
        total_risk = sum(c["effective_score"] for c in self.cves)
        curve = [total_risk]
        running = total_risk

        for cve_id in ordering:
            cve = cve_map[cve_id]
            running -= cve["effective_score"]
            time_penalty = cve.get("complexity_score", 5) / 100
            curve.append(max(0, running + time_penalty))

        return curve

    def _compute_position_confidence(self, top_orderings: List[Tuple]) -> Dict:
        positions = defaultdict(list)

        for _, ordering in top_orderings:
            for pos, cve_id in enumerate(ordering):
                positions[cve_id].append(pos)

        confidence = {}
        for cve_id, pos_list in positions.items():
            arr = np.array(pos_list)
            confidence[cve_id] = {
                "median_position": int(np.median(arr)),
                "ci_low": int(np.percentile(arr, 5)),
                "ci_high": int(np.percentile(arr, 95)),
                "stability": round(1 - (np.std(arr) / max(len(self.cves), 1)), 4),
            }

        return confidence
