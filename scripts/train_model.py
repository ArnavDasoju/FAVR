#!/usr/bin/env python3
"""
Train the FAVR patch priority ML model.

Generates synthetic vulnerability scenarios, runs Monte Carlo simulations
on each to get ground-truth optimal orderings, then trains a GradientBoosting
model to predict patch priority from CVE features.

Usage:
    python scripts/train_model.py [--scenarios 500]
"""
import sys
import os
import argparse
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from favr.optimization.ml_predictor import PatchPriorityPredictor


def main():
    parser = argparse.ArgumentParser(description="Train FAVR patch priority model")
    parser.add_argument(
        "--scenarios", type=int, default=500,
        help="Number of synthetic scenarios to generate (default: 500)"
    )
    args = parser.parse_args()

    predictor = PatchPriorityPredictor()

    print("=" * 60)
    print("FAVR Patch Priority Model Training")
    print("=" * 60)

    start = time.time()
    metrics = predictor.train(n_scenarios=args.scenarios)
    elapsed = time.time() - start

    print(f"\nTraining completed in {elapsed:.1f}s")
    print(f"\nResults:")
    print(f"  Train R2:  {metrics['train_r2']}")
    print(f"  Val R2:    {metrics['val_r2']}")
    print(f"  Val MAE:   {metrics['val_mae']}")
    print(f"  Samples:   {metrics['n_train']} train / {metrics['n_val']} val")

    print(f"\nFeature Importances:")
    for feat, imp in metrics["feature_importances"].items():
        bar = "#" * int(imp * 50)
        print(f"  {feat:<28s} {imp:.4f} {bar}")

    predictor.save()

    # Quick sanity check
    print("\nSanity check: predicting on a small synthetic scenario...")
    test_cves = [
        {
            "cve_id": "CVE-TEST-001", "affected_service": "api",
            "cvss_score": 9.8, "effective_score": 12.5,
            "complexity_score": 3, "estimated_patch_hours": 1,
            "service_criticality": 9, "compliance_relevant": True,
            "exploit_available": True, "prior_service_risk": 0.9,
            "propagated_service_risk": 0.95, "risk_multiplier": 1.05,
        },
        {
            "cve_id": "CVE-TEST-002", "affected_service": "db",
            "cvss_score": 4.2, "effective_score": 4.8,
            "complexity_score": 7, "estimated_patch_hours": 4,
            "service_criticality": 6, "compliance_relevant": False,
            "exploit_available": False, "prior_service_risk": 0.4,
            "propagated_service_risk": 0.5, "risk_multiplier": 1.25,
        },
        {
            "cve_id": "CVE-TEST-003", "affected_service": "frontend",
            "cvss_score": 7.5, "effective_score": 8.1,
            "complexity_score": 5, "estimated_patch_hours": 2,
            "service_criticality": 4, "compliance_relevant": False,
            "exploit_available": True, "prior_service_risk": 0.7,
            "propagated_service_risk": 0.75, "risk_multiplier": 1.07,
        },
    ]

    result = predictor.predict_priority(test_cves)
    print(f"  Predicted order: {result['optimal_order']}")
    print(f"  Risk score: {result['optimal_score']} (naive: {result['naive_score']})")
    print(f"  Improvement: {result['improvement_pct']}%")
    print(f"\nModel saved. Use run_ml_optimization() as a drop-in replacement.")


if __name__ == "__main__":
    main()
