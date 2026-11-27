import json
import os
from typing import List, Dict, Any
from config import PROJECT_NAME, TARGET_URL


class JSONReporter:
    """
    Concise, developer-focused JSON vulnerability reporter for SSRF Sentinel.
    Generates structured, clean, and deduplicated reporting conforming strictly
    to the required SSRF Sentinel schema.
    """

    # Structured knowledge base mapping unique vulnerability classes
    VULNERABILITY_CATALOG = {
        "INBAND_SECRET": {
            "name": "In-Band Internal Secret Disclosure",
            "technique": "Content-Based",
            "severity": "HIGH",
            "description": "The application accepts a user-controlled URL and fetches a restricted internal resource, returning confidential content directly in the HTTP response.",
            "impact": "An attacker can directly read sensitive internal files, API tokens, and private services that are not exposed to the public internet.",
            "recommendation": "Enforce a strict domain and IP allowlist on outgoing requests. Block loopback (127.0.0.0/8) and private IP ranges at the application and firewall level."
        },
        "INBAND_ADMIN": {
            "name": "Internal Admin Core Configuration Exposure",
            "technique": "Content-Based",
            "severity": "CRITICAL",
            "description": "The application forwards server-side requests to an internal administration endpoint, leaking database credentials and administrative session keys.",
            "impact": "Complete compromise of backend database infrastructure and administrative session impersonation.",
            "recommendation": "Isolate administrative endpoints on dedicated private management subnets with mutual TLS authentication. Restrict application egress."
        },
        "BYPASS_ALTERNATIVE_IP": {
            "name": "Alternative Host Representation Filter Bypass",
            "technique": "Content-Based / Bypass",
            "severity": "HIGH",
            "description": "The URL validation parser fails to normalize alternative host notations (e.g., decimal DWORD, octal, hex, shorthand, IPv6), allowing attackers to bypass standard loopback string filters.",
            "impact": "Bypasses naive blacklist filters that only match '127.0.0.1' or 'localhost', granting access to internal resources.",
            "recommendation": "Resolve the hostname or IP to its canonical socket address prior to validation, and evaluate the resolved IP address against an allowlist."
        },
        "REDIRECT_CHAIN": {
            "name": "Redirect-Based SSRF Chaining",
            "technique": "Redirect Chaining",
            "severity": "HIGH",
            "description": "The application's HTTP client automatically follows HTTP 301/302 redirects without re-validating the destination target, allowing an attacker to pivot into internal services.",
            "impact": "Bypasses initial URL validation checks by bouncing through external or open redirect endpoints to reach protected internal hosts.",
            "recommendation": "Disable automatic redirect following or strictly re-validate every redirect Location header against the authorized allowlist before following."
        },
        "LIMITED_RESPONSE": {
            "name": "Limited-Response SSRF",
            "technique": "Limited-Response",
            "severity": "MEDIUM",
            "description": "The application executes server-side requests to internal endpoints and reveals internal state through status codes (HTTP 204), custom headers, or response lengths.",
            "impact": "Enables internal port scanning, service discovery, and mapping of active internal infrastructure.",
            "recommendation": "Do not forward downstream HTTP status codes or custom headers to the user. Always return uniform application responses."
        },
        "BLIND_OOB": {
            "name": "Blind SSRF via Local Callback",
            "technique": "Blind / Out-of-Band",
            "severity": "HIGH",
            "description": "The application triggers an outbound HTTP request to a dedicated local callback listener without reflecting the response content to the user.",
            "impact": "Enables attackers to trigger unauthenticated internal API requests, interact with internal services, or interact with webhook endpoints.",
            "recommendation": "Enforce network egress filtering restricting the application from initiating connections to unauthorized ports and destinations."
        },
        "TIME_BASED": {
            "name": "Time-Based SSRF",
            "technique": "Time-Based",
            "severity": "MEDIUM",
            "description": "The application induces measurable, repeatable response delays when fetching slow or delayed internal resources.",
            "impact": "Enables attackers to infer whether internal network ports or endpoints are open based on round-trip latency differentials.",
            "recommendation": "Configure strict connection and read timeouts (e.g. 2.0 seconds or less) on all server-side HTTP clients."
        },
        "BOOLEAN_BASED": {
            "name": "Boolean-Based SSRF",
            "technique": "Boolean-Based",
            "severity": "MEDIUM",
            "description": "The application returns distinctly different HTTP statuses, lengths, or headers when evaluating downstream conditional queries.",
            "impact": "Allows attackers to infer internal data or configuration states through systematic true/false condition testing.",
            "recommendation": "Ensure the application returns uniform HTTP status codes, body lengths, and error responses regardless of downstream condition evaluations."
        }
    }

    def __init__(self, report_dir: str = "reports"):
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

    def _classify_probe(self, probe: dict) -> str:
        """Categorizes an individual probe into a unique vulnerability class."""
        probe_id = probe.get("extra_metadata", {}).get("probe_id", "")
        category = probe.get("vulnerability_category", "")

        if "ADMIN" in probe_id:
            return "INBAND_ADMIN"
        elif "BYPASS" in probe_id or "ENC" in probe_id:
            return "BYPASS_ALTERNATIVE_IP"
        elif "REDIR" in probe_id:
            return "REDIRECT_CHAIN"
        elif "INBAND" in category:
            return "INBAND_SECRET"
        elif "LIMITED" in category:
            return "LIMITED_RESPONSE"
        elif "BLIND" in category or "OOB" in category:
            return "BLIND_OOB"
        elif "TIME" in category:
            return "TIME_BASED"
        elif "BOOLEAN" in category:
            return "BOOLEAN_BASED"
        return "INBAND_SECRET"

    def consolidate_findings(self, raw_probes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Consolidates individual positive probes into distinct, unique vulnerability findings.
        Groups multiple supporting probes under their primary vulnerability class.
        """
        positive_probes = [p for p in raw_probes if p.get("detected") is True]
        grouped = {}

        for probe in positive_probes:
            vuln_class = self._classify_probe(probe)
            endpoint = probe.get("endpoint", "/fetch")
            param = probe.get("parameter", "url")
            key = (vuln_class, endpoint, param)

            if key not in grouped:
                grouped[key] = {
                    "vuln_class": vuln_class,
                    "endpoint": endpoint,
                    "parameter": param,
                    "highest_confidence": probe.get("confidence", "HIGH"),
                    "probes": []
                }

            grouped[key]["probes"].append(probe)
            # Elevate confidence if any supporting probe achieved LAB_CONFIRMED
            if probe.get("confidence") == "LAB_CONFIRMED":
                grouped[key]["highest_confidence"] = "LAB_CONFIRMED"

        vulnerabilities = []
        for idx, ((vuln_class, endpoint, param), data) in enumerate(grouped.items(), 1):
            catalog_entry = self.VULNERABILITY_CATALOG.get(vuln_class, self.VULNERABILITY_CATALOG["INBAND_SECRET"])

            # Collect unique evidence points across all supporting probes
            evidence_set = []
            for p in data["probes"]:
                for ev in p.get("evidence", []):
                    if ev not in evidence_set:
                        evidence_set.append(ev)

            vuln_id = f"SSRF-{idx:03d}"
            vulnerabilities.append({
                "id": vuln_id,
                "name": catalog_entry["name"],
                "technique": catalog_entry["technique"],
                "severity": catalog_entry["severity"],
                "confidence": data["highest_confidence"],
                "endpoint": endpoint,
                "parameter": param,
                "description": catalog_entry["description"],
                "evidence": evidence_set[:5],  # Keep evidence concise
                "impact": catalog_entry["impact"],
                "recommendation": catalog_entry["recommendation"]
            })

        return vulnerabilities

    def generate_report(
        self,
        endpoints: list,
        parameters: list,
        findings: list,
        total_tests: int = None,
        scan_duration_seconds: float = None,
        output_filename: str = "ssrf_report.json"
    ) -> str:
        """
        Generates clean, readable, developer-friendly JSON report conforming
        strictly to the requested schema.
        """
        # Consolidate raw probes into unique vulnerability findings
        vulnerabilities = self.consolidate_findings(findings)

        # Calculate counts
        tests_executed = total_tests if total_tests is not None else len(findings)
        positive_tests = sum(1 for f in findings if f.get("detected") is True)
        inconclusive_tests = sum(1 for f in findings if f.get("confidence") == "INCONCLUSIVE")
        negative_tests = tests_executed - positive_tests - inconclusive_tests

        report_data = {
            "project": PROJECT_NAME,
            "target": TARGET_URL,
            "scan_status": "COMPLETED",
            "summary": {
                "endpoints_discovered": len(endpoints),
                "parameters_tested": len(parameters),
                "tests_executed": tests_executed,
                "positive_tests": positive_tests,
                "negative_tests": negative_tests,
                "inconclusive_tests": inconclusive_tests,
                "unique_findings": len(vulnerabilities)
            },
            "vulnerabilities": vulnerabilities
        }

        output_path = os.path.join(self.report_dir, output_filename)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

        print(f"[REPORT] Clean JSON report generated successfully.")
        print(f"[REPORT] Location: {output_path}")
        print(f"[REPORT] Summary: {positive_tests} positive probes -> {len(vulnerabilities)} unique vulnerabilities.")

        return output_path
