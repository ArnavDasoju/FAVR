#!/usr/bin/env python3
"""
Train the FAVR vulnerability task-type classifier.

Generates synthetic vulnerabilities, labels them with the rule-based classifier,
then trains a GradientBoosting classifier and reports full metrics:
precision, recall, F1, confusion matrix.

Usage:
    python3 scripts/train_classifier.py [--samples 5000]
"""
import sys
import os
import argparse
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from favr.optimization.vuln_classifier import VulnClassifier, TASK_TYPES


def print_confusion_matrix(cm, labels):
    """Pretty-print a confusion matrix with labels."""
    # Abbreviate labels for display
    abbrev = {
        "critical-exploit": "crit-exp",
        "breaking-upgrade": "break-up",
        "security-refactor": "sec-ref",
        "multi-service-patch": "multi-svc",
        "config-hardening": "cfg-hard",
        "dependency-bump": "dep-bump",
        "compliance-patch": "comp-pat",
        "lockfile-regen": "lock-reg",
        "deep-analysis": "deep-anl",
        "test-generation": "test-gen",
    }
    short = [abbrev.get(l, l[:8]) for l in labels]
    col_width = 9

    # Header
    print(f"\n{'Predicted →':>{col_width + 12}}")
    print(f"{'Actual ↓':<{col_width + 2}}", end="")
    for s in short:
        print(f"{s:>{col_width}}", end="")
    print()
    print("-" * (col_width + 2 + col_width * len(short)))

    for i, row in enumerate(cm):
        print(f"{short[i]:<{col_width + 2}}", end="")
        for j, val in enumerate(row):
            if i == j and val > 0:
                print(f"\033[92m{val:>{col_width}}\033[0m", end="")  # green for correct
            elif val > 0:
                print(f"\033[91m{val:>{col_width}}\033[0m", end="")  # red for misclass
            else:
                print(f"{val:>{col_width}}", end="")
        print()


def main():
    parser = argparse.ArgumentParser(description="Train FAVR vulnerability classifier")
    parser.add_argument(
        "--samples", type=int, default=5000,
        help="Number of synthetic vulnerabilities to generate (default: 5000)"
    )
    args = parser.parse_args()

    classifier = VulnClassifier()

    print("=" * 65)
    print("FAVR Vulnerability Task-Type Classifier Training")
    print("=" * 65)

    start = time.time()
    metrics = classifier.train(n_samples=args.samples)
    elapsed = time.time() - start

    print(f"\nTraining completed in {elapsed:.1f}s")

    # Overall metrics
    print(f"\n{'Overall Metrics':=^65}")
    print(f"  Accuracy:           {metrics['accuracy']:.4f}")
    print(f"  Macro Precision:    {metrics['macro_precision']:.4f}")
    print(f"  Macro Recall:       {metrics['macro_recall']:.4f}")
    print(f"  Macro F1:           {metrics['macro_f1']:.4f}")
    print(f"  Weighted F1:        {metrics['weighted_f1']:.4f}")

    # Per-class metrics
    print(f"\n{'Per-Class Metrics':=^65}")
    print(f"  {'Task Type':<24s} {'Prec':>6s} {'Rec':>6s} {'F1':>6s} {'N':>5s}")
    print(f"  {'-' * 47}")
    for task in TASK_TYPES:
        m = metrics["per_class"][task]
        print(f"  {task:<24s} {m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} {m['support']:>5d}")

    # Confusion matrix
    print(f"\n{'Confusion Matrix':=^65}")
    print_confusion_matrix(metrics["confusion_matrix"], TASK_TYPES)

    # Feature importances
    print(f"\n{'Feature Importances':=^65}")
    for feat, imp in metrics["feature_importances"].items():
        bar = "#" * int(imp * 40)
        print(f"  {feat:<28s} {imp:.4f} {bar}")

    # Save
    classifier.save()

    # Sanity check
    print(f"\n{'Sanity Check':=^65}")
    test_cases = [
        {
            "description": "Remote code execution with public exploit available in log4j",
            "known_exploit": False, "in_kev": True, "has_public_exploit": True,
            "cvss_score": 10.0, "epss_score": 0.97, "complexity": "high",
            "severity": "critical", "affected_service_ids": ["api"],
            "compliance_violations": [], "compliance_deadline_days": None,
            "current_major_version": 2, "patched_major_version": 2,
        },
        {
            "description": "Minor denial of service in JSON parsing library",
            "known_exploit": False, "in_kev": False, "has_public_exploit": False,
            "cvss_score": 4.3, "epss_score": 0.02, "complexity": "low",
            "severity": "medium", "affected_service_ids": ["api"],
            "compliance_violations": [], "compliance_deadline_days": None,
            "current_major_version": 3, "patched_major_version": 3,
        },
        {
            "description": "TLS certificate validation bypass allows MITM attack",
            "known_exploit": False, "in_kev": False, "has_public_exploit": False,
            "cvss_score": 6.5, "epss_score": 0.08, "complexity": "medium",
            "severity": "medium", "affected_service_ids": ["gateway"],
            "compliance_violations": [], "compliance_deadline_days": None,
            "current_major_version": 1, "patched_major_version": 1,
        },
        {
            "description": "SQL injection in user authentication endpoint",
            "known_exploit": False, "in_kev": False, "has_public_exploit": False,
            "cvss_score": 9.8, "epss_score": 0.45, "complexity": "high",
            "severity": "critical", "affected_service_ids": ["api", "auth"],
            "compliance_violations": [], "compliance_deadline_days": None,
            "current_major_version": 2, "patched_major_version": 2,
        },
        {
            "description": "Chained vulnerability in transitive dependency allows escalation",
            "known_exploit": False, "in_kev": False, "has_public_exploit": False,
            "cvss_score": 8.5, "epss_score": 0.15, "complexity": "high",
            "severity": "high", "affected_service_ids": ["api"],
            "compliance_violations": [], "compliance_deadline_days": None,
            "current_major_version": 1, "patched_major_version": 1,
        },
    ]

    for tc in test_cases:
        result = classifier.predict(tc)
        desc_short = tc["description"][:50]
        print(f"  \"{desc_short}...\"")
        print(f"    → {result['predicted_type']} (confidence: {result['confidence']:.2f})")
        top3 = list(result["probabilities"].items())[:3]
        probs_str = ", ".join(f"{k}: {v:.2f}" for k, v in top3)
        print(f"    Top 3: {probs_str}\n")

    print("Done. Classifier ready for use.")


if __name__ == "__main__":
    main()
