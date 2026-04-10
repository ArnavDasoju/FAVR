from .base import Agent


class ScannerAgent(Agent):
    """Scans codebase to find specific instances of vulnerabilities."""

    name = "scanner_agent"
    description = "Analyzes codebase to locate affected files, packages, and code patterns per CVE"

    def process(self, input_data: dict) -> dict:
        """
        Input: cves, scan_results (pre-computed), services
        Output: enriched scan results with severity assessments
        """
        cves = input_data["cves"]
        scan_results = input_data.get("scan_results", [])
        services = {s["name"]: s for s in input_data.get("services", [])}

        self._log("Starting codebase scan across all services...")

        findings = []
        for scan in scan_results:
            cve = next((c for c in cves if c["cve_id"] == scan["cve_id"]), None)
            if not cve:
                continue

            service = services.get(scan["service"], {})
            finding = {
                "cve_id": scan["cve_id"],
                "service": scan["service"],
                "severity": cve["severity"],
                "cvss_score": cve["cvss_score"],
                "files_affected": scan["files_affected"],
                "packages": scan["packages"],
                "scan_confidence": scan.get("scan_confidence", 0.9),
                "code_patterns_found": scan.get("code_patterns_found", []),
                "service_criticality": service.get("criticality", "MEDIUM"),
                "pci_scope": service.get("pci_scope", False),
                "exploit_available": cve.get("exploit_available", False),
                "conflict_detected": scan.get("conflict_detected"),
            }
            findings.append(finding)

            self._log(
                f"Found {cve['cve_id']} ({cve['severity']}) in {scan['service']}: "
                f"{len(scan['files_affected'])} files, "
                f"{len(scan.get('packages', []))} packages affected"
            )

            if scan.get("conflict_detected"):
                conflict = scan["conflict_detected"]
                self.send_message(
                    "orchestrator",
                    "INFORM",
                    {
                        "summary": f"Dependency conflict detected for {cve['cve_id']}",
                        "reason": conflict["description"],
                        "cve_id": cve["cve_id"],
                        "conflict": conflict,
                    },
                    priority="high",
                )

        self._log(f"Scan complete: {len(findings)} vulnerabilities identified across {len(set(f['service'] for f in findings))} services")

        self.send_message(
            "orchestrator",
            "INFORM",
            {
                "summary": f"Scan complete: {len(findings)} vulnerabilities found",
                "total_findings": len(findings),
                "by_severity": {
                    sev: len([f for f in findings if f["severity"] == sev])
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
                },
                "conflicts_found": len([f for f in findings if f.get("conflict_detected")]),
            },
        )

        return {"findings": findings}
