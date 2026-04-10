import json
import os
import time
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from ..agents.orchestrator import OrchestratorAgent

app = FastAPI(title="FAVR API", version="1.0.0", description="Find, Analyze, Verify, Resolve — Vulnerability Prioritization Pipeline")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
orchestrator: Optional[OrchestratorAgent] = None
pipeline_result: Optional[dict] = None
pipeline_running = False

SYNTHETIC_DIR = Path(__file__).parent.parent.parent / "synthetic"


def load_json(filename: str):
    with open(SYNTHETIC_DIR / filename) as f:
        return json.load(f)


def get_scenario():
    return {
        "services": load_json("services.json"),
        "dependencies": load_json("dependencies.json"),
        "cves": load_json("cves.json"),
        "constraints": load_json("constraints.json"),
        "scan_results": load_json("scan_results.json"),
    }


# --- Pipeline endpoints ---

@app.post("/api/pipeline/run")
async def run_pipeline():
    global orchestrator, pipeline_result, pipeline_running
    if pipeline_running:
        raise HTTPException(status_code=409, detail="Pipeline already running")

    pipeline_running = True
    try:
        orchestrator = OrchestratorAgent()
        scenario = get_scenario()
        pipeline_result = orchestrator.run_pipeline(scenario)
        return {"status": "complete", "elapsed": pipeline_result["pipeline_metadata"]["elapsed_seconds"]}
    finally:
        pipeline_running = False


@app.get("/api/pipeline/status")
async def pipeline_status():
    if orchestrator:
        return orchestrator.get_status()
    return {"step": 0, "total_steps": 6, "current": "idle", "progress": 0}


# --- Vulnerability endpoints ---

@app.get("/api/vulnerabilities")
async def list_vulnerabilities():
    if not pipeline_result:
        cves = load_json("cves.json")
        return {"vulnerabilities": cves, "pipeline_run": False}

    propagated = pipeline_result["optimization"]["bayesian"]["propagated_cves"]
    optimal_order = pipeline_result["optimization"]["monte_carlo"]["optimal_order"]
    confidence = pipeline_result["optimization"]["monte_carlo"]["confidence_intervals"]
    plans_map = {p["cve_id"]: p for p in pipeline_result["remediation_plans"]}

    enriched = []
    for cve in propagated:
        cve_id = cve["cve_id"]
        rank = optimal_order.index(cve_id) + 1 if cve_id in optimal_order else None
        plan = plans_map.get(cve_id, {})
        ci = confidence.get(cve_id, {})

        enriched.append({
            **cve,
            "rank": rank,
            "confidence_interval": ci,
            "remediation_status": "verified" if plan.get("verified") else "pending",
            "estimated_hours": plan.get("estimated_hours"),
            "is_blocked": plan.get("is_blocked", False),
        })

    enriched.sort(key=lambda x: x.get("rank", 999))
    return {"vulnerabilities": enriched, "pipeline_run": True}


@app.get("/api/vulnerabilities/{cve_id}")
async def get_vulnerability(cve_id: str):
    if not pipeline_result:
        cves = load_json("cves.json")
        cve = next((c for c in cves if c["cve_id"] == cve_id), None)
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        return cve

    propagated = pipeline_result["optimization"]["bayesian"]["propagated_cves"]
    cve = next((c for c in propagated if c["cve_id"] == cve_id), None)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    plan = next((p for p in pipeline_result["remediation_plans"] if p["cve_id"] == cve_id), None)
    scan = next((f for f in pipeline_result["scan"]["findings"] if f["cve_id"] == cve_id), None)
    ci = pipeline_result["optimization"]["monte_carlo"]["confidence_intervals"].get(cve_id, {})
    optimal_order = pipeline_result["optimization"]["monte_carlo"]["optimal_order"]
    rank = optimal_order.index(cve_id) + 1 if cve_id in optimal_order else None

    compliance_flags = [
        f for f in pipeline_result["compliance"]["compliance_flags"]
        if f.get("cve_id") == cve_id
    ]

    return {
        **cve,
        "rank": rank,
        "confidence_interval": ci,
        "scan_details": scan,
        "remediation_plan": plan,
        "compliance_flags": compliance_flags,
    }


# --- Plan endpoints ---

@app.get("/api/plan")
async def get_plan():
    if not pipeline_result:
        raise HTTPException(status_code=404, detail="Pipeline not yet run")

    optimal = pipeline_result["optimization"]["monte_carlo"]["optimal_order"]
    plans_map = {p["cve_id"]: p for p in pipeline_result["remediation_plans"]}
    propagated_map = {c["cve_id"]: c for c in pipeline_result["optimization"]["bayesian"]["propagated_cves"]}

    ordered_plan = []
    for i, cve_id in enumerate(optimal):
        plan = plans_map.get(cve_id, {})
        cve = propagated_map.get(cve_id, {})
        ordered_plan.append({
            "rank": i + 1,
            "cve_id": cve_id,
            "severity": cve.get("severity"),
            "service": cve.get("affected_service"),
            "effective_score": cve.get("effective_score"),
            "estimated_hours": plan.get("estimated_hours"),
            "is_blocked": plan.get("is_blocked", False),
            "verified": plan.get("verified", False),
        })

    return {"plan": ordered_plan}


class ReorderRequest(BaseModel):
    ordering: list[str]


@app.put("/api/plan/reorder")
async def reorder_plan(req: ReorderRequest):
    if not pipeline_result:
        raise HTTPException(status_code=404, detail="Pipeline not yet run")
    pipeline_result["optimization"]["monte_carlo"]["optimal_order"] = req.ordering
    return {"status": "reordered", "new_order": req.ordering}


# --- Agent log ---

@app.get("/api/agents/log")
async def agent_log():
    if not pipeline_result:
        return {"log": []}
    return {"log": pipeline_result["agent_log"]}


# --- Monte Carlo results ---

@app.get("/api/monte-carlo/results")
async def monte_carlo_results():
    if not pipeline_result:
        raise HTTPException(status_code=404, detail="Pipeline not yet run")
    return pipeline_result["optimization"]["monte_carlo"]


# --- Services ---

@app.get("/api/services")
async def list_services():
    services = load_json("services.json")
    if pipeline_result:
        for svc in services:
            status = pipeline_result["services"].get(svc["name"], {})
            svc["vulnerability_count"] = status.get("vulnerability_count", 0)
            svc["propagated_risk"] = status.get("propagated_risk", 0)
            svc["severities"] = status.get("severities", {})
    return {"services": services}


# --- Dependencies ---

@app.get("/api/dependencies")
async def get_dependencies():
    deps = load_json("dependencies.json")
    return {"dependencies": deps}


# --- Report ---

@app.get("/api/report")
async def get_report():
    if not pipeline_result:
        raise HTTPException(status_code=404, detail="Pipeline not yet run")
    return {
        "executive_summary": pipeline_result["executive_summary"],
        "risk_assessment": pipeline_result["risk_assessment"],
        "pareto_profiles": pipeline_result["optimization"]["pareto"]["profiles"],
    }


# --- Bayesian results ---

@app.get("/api/bayesian/results")
async def bayesian_results():
    if not pipeline_result:
        raise HTTPException(status_code=404, detail="Pipeline not yet run")
    return pipeline_result["optimization"]["bayesian"]


# --- Health ---

@app.get("/api/health")
async def health():
    return {"status": "ok", "pipeline_run": pipeline_result is not None}
