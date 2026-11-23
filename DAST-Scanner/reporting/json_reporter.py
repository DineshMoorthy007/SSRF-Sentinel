import json
import os
from datetime import datetime, timezone
from config import PROJECT_NAME, TARGET_URL


class JSONReporter:
    """
    Compact, beginner-friendly JSON vulnerability reporter for SSRF Sentinel.
    Generates a simple, clean, and easily understandable vulnerability report
    designed for faculty members, interviewers, and beginners.
    """

    FINDING_TEMPLATES = {
        "INBAND_SECRET_PROBE": {
            "vulnerability_name": "Internal Secret Exposure",
            "detection_technique": "In-Band / Content-Based",
            "severity": "High",
            "description": "The application fetched a simulated internal test secret and returned its restricted content directly in the response.",
            "evidence": "The internal verification marker (SSRF_SENTINEL_INTERNAL_ACCESS_2026) was found in the application's response.",
            "potential_impact": "An attacker could read sensitive internal files, API keys, and private data not exposed to the public internet.",
            "recommended_fix": "Validate and restrict destination URLs. Block the server from sending requests to loopback and private internal network addresses."
        },
        "INBAND_ADMIN_CONFIG": {
            "vulnerability_name": "Internal Admin Configuration Leakage",
            "detection_technique": "In-Band / Content-Based",
            "severity": "High",
            "description": "The application fetched an internal administrative configuration endpoint and exposed simulated database and session keys.",
            "evidence": "The internal admin verification marker (SSRF_SENTINEL_INBAND_FULL_ACCESS) and internal headers were returned in the response.",
            "potential_impact": "An attacker could obtain administrative credentials and database connection details to compromise backend infrastructure.",
            "recommended_fix": "Enforce a strict domain allowlist for outgoing requests and prevent backend response bodies from being forwarded to users."
        },
        "INBAND_STATUS_PROBE": {
            "vulnerability_name": "Internal Service Metadata Exposure",
            "detection_technique": "In-Band / Content-Based",
            "severity": "Medium",
            "description": "The application fetched an internal heartbeat service and exposed internal environment and service details.",
            "evidence": "The internal test service identifier was returned in the response body.",
            "potential_impact": "An attacker could map internal network topology and identify active internal services.",
            "recommended_fix": "Restrict outgoing requests to authorized external services and disable access to internal diagnostic endpoints."
        },
        "LIMITED_STATUS_ONLY": {
            "vulnerability_name": "Internal Request Execution via HTTP 204",
            "detection_technique": "Limited-Response",
            "severity": "Medium",
            "description": "The application processed a request to an internal endpoint that returns an HTTP 204 No Content status, forwarding the success status.",
            "evidence": "The server returned HTTP 204 No Content with an empty body, confirming the internal request succeeded.",
            "potential_impact": "An attacker could use status codes to probe and map live internal network hosts and open ports.",
            "recommended_fix": "Do not forward raw downstream HTTP status codes to users. Always return uniform application responses."
        },
        "LIMITED_HEADER_ONLY": {
            "vulnerability_name": "Internal Header Information Leakage",
            "detection_technique": "Limited-Response",
            "severity": "Medium",
            "description": "The application forwarded custom metadata headers from an internal service while suppressing the response body.",
            "evidence": "The internal test header marker (X-Internal-Marker: SSRF_HEADER_ONLY_FLAG) was present in the response headers.",
            "potential_impact": "Internal headers can leak backend server details, internal routing names, and software versions.",
            "recommended_fix": "Strip all internal headers before sending the response to the client, or avoid forwarding internal headers entirely."
        },
        "LIMITED_TRUNCATED": {
            "vulnerability_name": "Truncated Internal Response Disclosure",
            "detection_technique": "Limited-Response",
            "severity": "Medium",
            "description": "The application fetched an internal resource that returned a partially truncated data string.",
            "evidence": "A partial internal secret fragment was identified in the response body.",
            "potential_impact": "Partial data leaks can expose fragments of internal secrets, tokens, or memory buffers.",
            "recommended_fix": "Block requests to internal IP addresses and sanitize outgoing response streams."
        },
        "LIMITED_GENERIC": {
            "vulnerability_name": "Generic Internal Execution Confirmation",
            "detection_technique": "Limited-Response",
            "severity": "Low",
            "description": "The application accessed an internal resource that responded with a generic execution confirmation.",
            "evidence": "The server returned a success confirmation message distinct from the baseline rejection response.",
            "potential_impact": "An attacker could confirm the existence and availability of hidden internal APIs.",
            "recommended_fix": "Return uniform error messages when a requested URL is rejected, without disclosing execution state."
        },
        "LIMITED_SUPPRESSED": {
            "vulnerability_name": "Policy-Suppressed Content Disclosure",
            "detection_technique": "Limited-Response",
            "severity": "Low",
            "description": "The application processed an internal request where content filtering was triggered, revealing that an internal resource was intercepted.",
            "evidence": "The response contained an active policy suppression indicator ([CONTENT_SUPPRESSED_BY_POLICY]).",
            "potential_impact": "Confirms to an attacker that the targeted internal endpoint exists and triggers security filter rules.",
            "recommended_fix": "Reject unauthorized internal destination URLs at the network layer rather than relying only on response filtering."
        },
        "BLIND_OOB_CALLBACK": {
            "vulnerability_name": "Blind SSRF via Local Callback",
            "detection_technique": "Blind / Out-of-Band",
            "severity": "High",
            "description": "The application made a server-side HTTP request to a local test listener on port 8090 without returning the response content.",
            "evidence": "The dedicated local callback receiver confirmed an incoming request with the matching test tracking token.",
            "potential_impact": "An attacker could trigger requests to unauthenticated internal services, webhook systems, or trigger remote callbacks.",
            "recommended_fix": "Block the server from initiating arbitrary outbound HTTP connections and restrict egress network routing."
        },
        "TIME_BASED_SSRF": {
            "vulnerability_name": "Time-Based Internal Request Detection",
            "detection_technique": "Time-Based",
            "severity": "Medium",
            "description": "The application took noticeably longer to respond when asked to fetch an internally delayed endpoint compared to an immediate endpoint.",
            "evidence": "A consistent delay of approximately 2.0 seconds was measured across multiple probe iterations compared to fast baseline requests.",
            "potential_impact": "An attacker could infer whether internal IP addresses or ports are open based on response latency.",
            "recommended_fix": "Set strict connection and read timeouts on server-side requests (e.g., 2 seconds or less)."
        },
        "BOOLEAN_BASED_SSRF": {
            "vulnerability_name": "Boolean-Based Internal Request Detection",
            "detection_technique": "Boolean-Based",
            "severity": "Medium",
            "description": "The application returned clearly different responses when internal true and false test conditions were evaluated.",
            "evidence": "The server returned HTTP 200 (large response) for the true condition and HTTP 404 (small response) for the false condition.",
            "potential_impact": "An attacker could exfiltrate internal data bit-by-bit using conditional true/false queries.",
            "recommended_fix": "Ensure the application returns consistent HTTP status codes and response formats regardless of downstream conditions."
        }
    }

    def __init__(self):
        self.report_directory = "reports"
        os.makedirs(self.report_directory, exist_ok=True)

    def _format_finding(self, index, item):
        probe_id = item.get("extra_metadata", {}).get("probe_id", "")
        category = item.get("vulnerability_category", "")

        # Match against known probe templates
        template = None
        if probe_id in self.FINDING_TEMPLATES:
            template = self.FINDING_TEMPLATES[probe_id]
        elif category in self.FINDING_TEMPLATES:
            template = self.FINDING_TEMPLATES[category]
        elif "BLIND" in category or "OOB" in category:
            template = self.FINDING_TEMPLATES["BLIND_OOB_CALLBACK"]
        elif "TIME" in category:
            template = self.FINDING_TEMPLATES["TIME_BASED_SSRF"]
        elif "BOOLEAN" in category:
            template = self.FINDING_TEMPLATES["BOOLEAN_BASED_SSRF"]

        if template:
            vuln_name = template["vulnerability_name"]
            technique = template["detection_technique"]
            severity = template["severity"]
            description = template["description"]
            evidence = template["evidence"]
            impact = template["potential_impact"]
            fix = template["recommended_fix"]
        else:
            vuln_name = "Server-Side Request Forgery"
            technique = item.get("detection_technique", "SSRF Probing")
            severity = "Medium"
            description = "The application allowed its server to fetch an internal resource based on user-supplied input."
            evidence = item.get("evidence", ["Observed server response indicates internal request execution."])[0]
            impact = "An attacker could potentially use this functionality to access sensitive internal resources."
            fix = "Validate and restrict all destination URLs. Block unauthorized requests to internal network resources."

        return {
            "id": f"SSRF-{index:02d}",
            "vulnerability_name": vuln_name,
            "detection_technique": technique,
            "severity": severity,
            "affected_endpoint": item.get("endpoint", "/fetch"),
            "affected_parameter": item.get("parameter", "url"),
            "description": description,
            "evidence": evidence,
            "potential_impact": impact,
            "recommended_fix": fix
        }

    def generate_report(
        self,
        endpoints,
        parameters,
        findings,
        total_tests=None,
        scan_duration_seconds=0.0
    ):
        if total_tests is None:
            total_tests = len(findings)

        # Categorize test results
        positive_tests = [f for f in findings if f.get("detected") and f.get("test_outcome") == "POSITIVE"]
        negative_tests = [f for f in findings if not f.get("detected") and f.get("test_outcome") == "NEGATIVE"]
        inconclusive_tests = [f for f in findings if f.get("confidence") == "INCONCLUSIVE" or f.get("test_outcome") == "FAILED"]

        # Build clean, simplified findings list
        vulnerability_findings = []
        for index, item in enumerate(positive_tests, start=1):
            vulnerability_findings.append(self._format_finding(index, item))

        report = {
            "scan_information": {
                "project_name": PROJECT_NAME,
                "target_url": TARGET_URL,
                "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "scan_status": "COMPLETED"
            },
            "scan_summary": {
                "endpoints_discovered": len(endpoints),
                "parameters_analysed": len(parameters),
                "total_tests_performed": total_tests,
                "positive_results": len(positive_tests),
                "negative_results": len(negative_tests),
                "inconclusive_results": len(inconclusive_tests)
            },
            "vulnerability_findings": vulnerability_findings
        }

        report_path = os.path.join(self.report_directory, "ssrf_report.json")

        with open(report_path, "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=4, ensure_ascii=False)

        print("\n[REPORT] Clean JSON report generated successfully.")
        print(f"[REPORT] Location: {os.path.abspath(report_path)}")

        return report_path
