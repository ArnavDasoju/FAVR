"""Run FAVR pipeline from CLI or start the API server."""
import argparse
import json
import sys
from pathlib import Path


def run_cli(scenario_dir: str):
    """Run pipeline from command line and print results."""
    from ..agents.orchestrator import OrchestratorAgent

    scenario_path = Path(scenario_dir)
    scenario = {
        "services": json.load(open(scenario_path / "services.json")),
        "dependencies": json.load(open(scenario_path / "dependencies.json")),
        "cves": json.load(open(scenario_path / "cves.json")),
        "constraints": json.load(open(scenario_path / "constraints.json")),
        "scan_results": json.load(open(scenario_path / "scan_results.json")),
    }

    print("FAVR Pipeline - Starting...")
    print(f"Scenario: {len(scenario['cves'])} CVEs, {len(scenario['services'])} services\n")

    orch = OrchestratorAgent()
    result = orch.run_pipeline(scenario)

    es = result["executive_summary"]
    print("=" * 60)
    print("EXECUTIVE SUMMARY")
    print("=" * 60)
    print(f"Total vulnerabilities: {es['total_vulnerabilities']}")
    print(f"  Critical: {es['critical']}, High: {es['high']}, Medium: {es['medium']}, Low: {es['low']}")
    print(f"Risk score: {es['risk_before']:.1f} -> {es['risk_after']}")
    print(f"Monte Carlo improvement: {es['monte_carlo_improvement']}%")
    print(f"Conflicts detected/resolved: {es['conflicts_detected']}/{es['conflicts_resolved']}")
    print(f"Compliance escalations: {es['compliance_escalations']}")
    print(f"Total remediation hours: {es['total_remediation_hours']:.1f}")
    print(f"Pareto profiles: {es['pareto_profiles_available']}")
    print(f"Pipeline time: {result['pipeline_metadata']['elapsed_seconds']}s")

    print("\n" + "=" * 60)
    print("OPTIMAL PATCHING ORDER")
    print("=" * 60)
    mc = result["optimization"]["monte_carlo"]
    cve_map = {c["cve_id"]: c for c in scenario["cves"]}
    for i, cve_id in enumerate(mc["optimal_order"]):
        cve = cve_map.get(cve_id, {})
        ci = mc["confidence_intervals"].get(cve_id, {})
        print(f"  {i+1:2d}. {cve_id} ({cve.get('severity', '?'):8s}) "
              f"[{cve.get('affected_service', '?')}] "
              f"CVSS: {cve.get('cvss_score', '?')} "
              f"CI: [{ci.get('ci_low', '?')}-{ci.get('ci_high', '?')}]")

    print("\n" + "=" * 60)
    print("AGENT COMMUNICATION LOG")
    print("=" * 60)
    for msg in result["agent_log"]:
        icon = {"BLOCK": "X", "ESCALATE": "!", "RESOLVE": "+", "INFORM": "-"}.get(msg["type"], "?")
        summary = msg["payload"].get("summary", msg["payload"].get("reason", ""))[:70]
        print(f"  [{icon}] {msg['from']:20s} -> {msg['to']:20s} | {summary}")

    # Write full results
    output_path = Path("favr_results.json")
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)
    print(f"\nFull results written to {output_path}")


def run_server(host: str = "0.0.0.0", port: int = 8000):
    """Start the FastAPI server."""
    import uvicorn
    print(f"Starting FAVR API server on {host}:{port}")
    uvicorn.run("favr.pipeline.server:app", host=host, port=port, reload=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FAVR Pipeline")
    parser.add_argument("--scenario", "-s", default="synthetic/", help="Path to scenario directory")
    parser.add_argument("--server", action="store_true", help="Start API server instead of CLI")
    parser.add_argument("--port", type=int, default=8000, help="API server port")
    args = parser.parse_args()

    if args.server:
        run_server(port=args.port)
    else:
        run_cli(args.scenario)
