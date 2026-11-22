import json
import os
from datetime import datetime, timezone
from config import PROJECT_NAME, VERSION, TARGET_URL


class JSONReporter:
    """
    Standards-compliant, human-readable JSON vulnerability reporting system for SSRF Sentinel.
    Produces clear, executive-ready assessment reports that explain what was tested,
    what was detected, why it matters, and how to fix it in simple, accessible language
    while strictly preserving raw technical evidence.
    """

    TECHNIQUE_METADATA = {
        "INBAND_SSRF": {
            "name": "In-Band / Content-Based SSRF",
            "description": "Checks if the application returns internal resource content directly to the user.",
            "remediation": (
                "Enforce strict destination allowlists on the server-side HTTP client. "
                "Prevent the reflection of internal response bodies to callers. Implement network-level "
                "egress filtering blocking private/loopback IP address ranges (RFC 1918 / RFC 5735)."
            )
        },
        "LIMITED_RESPONSE_SSRF": {
            "name": "Limited-Response SSRF",
            "description": "Checks if partial internal request artifacts (status codes, headers, truncated fragments) leak back to the user.",
            "remediation": (
                "Suppress downstream HTTP status codes, headers, and error fragments. "
                "Return standardized generic responses regardless of internal request outcome. "
                "Enforce egress filtering on server-side request forwarders."
            )
        },
        "BLIND_OOB_SSRF": {
            "name": "Blind / Out-of-Band SSRF",
            "description": "Checks if the server initiates external requests without returning the response, verified via an independent callback receiver.",
            "remediation": (
                "Isolate backend request forwarders within a restricted network zone with default-deny "
                "egress rules. Enforce proxy authentication and block unauthorized outbound TCP/UDP traffic."
            )
        },
        "TIME_BASED_SSRF": {
            "name": "Time-Based SSRF",
            "description": "Checks for measurable differences in server response time caused by delays introduced during internal requests.",
            "remediation": (
                "Enforce aggressive socket connect and read timeouts (<= 2s) on internal HTTP requests. "
                "Decouple backend request execution from client HTTP lifecycles using asynchronous background workers."
            )
        },
        "BOOLEAN_BASED_SSRF": {
            "name": "Boolean-Based SSRF",
            "description": "Checks if the application produces distinguishable responses when evaluating true versus false internal conditions.",
            "remediation": (
                "Normalize server-side application responses so conditional downstream queries do not produce "
                "measurable divergences in HTTP status codes, content lengths, or structural evaluation headers."
            )
        },
        "NEGATIVE_CONTROL": {
            "name": "Negative Control Calibration",
            "description": "Verifies that baseline public requests do not falsely trigger SSRF vulnerability indicators.",
            "remediation": "N/A - Control calibration test."
        }
    }

    CONFIDENCE_SCALE = {
        "LAB_CONFIRMED": "The expected verification evidence was successfully observed in the controlled test environment.",
        "HIGH": "Strong evidence of SSRF-related behaviour was observed.",
        "MEDIUM": "Some evidence was observed, but additional verification is required.",
        "LOW": "Weak evidence that may be caused by other application behaviour.",
        "INCONCLUSIVE": "The test did not provide enough information for a reliable conclusion."
    }

    GLOSSARY = {
        "In-Band SSRF": "The application returns the internal resource's content directly in its response to the user.",
        "Limited-Response SSRF": "Detection when only partial information about an internal request (such as a status code, header, or error message) is returned.",
        "Blind / Out-of-Band SSRF": "The application makes an internal request without showing its response, detected using an independent callback receiver.",
        "Time-Based SSRF": "Detection using measurable differences in server response time caused by internal delays.",
        "Boolean-Based SSRF": "Detection by comparing server responses to true and false conditions."
    }

    CONSOLIDATED_RECOMMENDATIONS = [
        {
            "priority": "HIGH",
            "title": "Implement Strict Destination Allowlisting",
            "description": (
                "Restrict the URL-fetching functionality to an explicit allowlist of authorized external domains and IP addresses. "
                "Explicitly reject requests to loopback addresses (127.0.0.0/8), private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), "
                "and cloud metadata endpoints (169.254.169.254)."
            )
        },
        {
            "priority": "HIGH",
            "title": "Enforce Network-Level Egress Filtering",
            "description": (
                "Configure host firewall and network routing rules so that the application server cannot initiate outbound connections "
                "to internal microservices, databases, or unauthorized local ports. Use a dedicated egress proxy for necessary outbound web requests."
            )
        },
        {
            "priority": "MEDIUM",
            "title": "Suppress Downstream Response Details",
            "description": (
                "Do not relay raw response bodies, headers, or internal error messages back to clients. "
                "Always return generic, standardized status responses regardless of internal request outcomes to eliminate limited-response leakage."
            )
        },
        {
            "priority": "MEDIUM",
            "title": "Set Strict Request Timeouts",
            "description": (
                "Enforce short, bounded socket connection and read timeouts (e.g. <= 2 seconds) on outgoing requests. "
                "This prevents time-based inference attacks and shields the server against request starvation denial-of-service."
            )
        },
        {
            "priority": "LOW",
            "title": "Normalize Conditional Responses",
            "description": (
                "Ensure that application responses have uniform HTTP status codes, headers, and body lengths "
                "regardless of whether a downstream condition is true or false, eliminating Boolean-based side-channel probing."
            )
        }
    ]

    def __init__(self):
        self.report_directory = "reports"
        os.makedirs(self.report_directory, exist_ok=True)

    def _generate_human_descriptions(self, item):
        """Generates plain English descriptions for what was tested, what happened, and why it matters."""
        probe_id = item.get("extra_metadata", {}).get("probe_id", "")
        category = item.get("vulnerability_category", "")
        payload = item.get("payload", "")

        # Default fallbacks
        vuln_name = "Server-Side Request Forgery"
        what_tested = f"Tested endpoint with probe URL: {payload}"
        what_happened = "The application processed the request and exhibited observable internal behavior."
        why_matters = "Allows attackers to instruct the backend server to make unauthorized requests to internal resources."
        human_evidence = "Observed server behavior indicates interaction with the requested destination."

        # Probe-specific descriptions
        if probe_id == "INBAND_SECRET_PROBE":
            vuln_name = "In-Band SSRF - Internal Secret Data Exposure"
            what_tested = "Instructed the server to fetch the internal secret resource at http://127.0.0.1:8081/internal/secret."
            what_happened = "The server retrieved the internal resource and returned the internal secret data and mock service headers directly to the client."
            why_matters = "An external attacker can abuse this parameter to access private internal services, stealing authentication credentials and restricted internal data."
            human_evidence = "The application returned content from an internal service through its URL-fetching functionality."

        elif probe_id == "INBAND_ADMIN_CONFIG":
            vuln_name = "In-Band SSRF - Administrative Configuration Exposure"
            what_tested = "Instructed the server to fetch the internal admin configuration vault at http://127.0.0.1:8081/internal/admin/config."
            what_happened = "The server fetched the administrative configuration and exposed database connection strings and session keys."
            why_matters = "Leaking internal administrative credentials allows attackers to pivot to internal databases and gain full administrative control."
            human_evidence = "The response revealed sensitive internal database URIs, admin session keys, and network topology metadata."

        elif probe_id == "INBAND_STATUS_PROBE":
            vuln_name = "In-Band SSRF - Internal Service Metadata Exposure"
            what_tested = "Instructed the server to fetch the internal health status service at http://127.0.0.1:8081/internal/status."
            what_happened = "The server fetched and returned internal service environment metadata."
            why_matters = "Disclosing internal network details helps attackers map internal network architecture and identify internal service names."
            human_evidence = "The application returned the internal service heartbeat and environment classification."

        elif probe_id == "LIMITED_STATUS_ONLY":
            vuln_name = "Limited-Response SSRF - Status-Only Downstream Leakage"
            what_tested = "Instructed the server to fetch an internal endpoint that returns an HTTP 204 No Content status code."
            what_happened = "The public application forwarded the HTTP 204 status with an empty body, confirming the internal request succeeded."
            why_matters = "Even without seeing the response body, receiving distinct HTTP status codes allows an attacker to port scan and map internal services."
            human_evidence = "The server returned HTTP 204 No Content, confirming the internal request was executed successfully."

        elif probe_id == "LIMITED_HEADER_ONLY":
            vuln_name = "Limited-Response SSRF - Header-Only Information Leakage"
            what_tested = "Instructed the server to fetch an internal endpoint configured to return custom metadata headers without a response body."
            what_happened = "The public application forwarded internal response headers (X-Internal-Marker) while omitting the body."
            why_matters = "Internal headers can leak backend server software, routing paths, internal hostnames, and application state."
            human_evidence = "Internal headers were leaked into the public response while the response body was empty."

        elif probe_id == "LIMITED_TRUNCATED":
            vuln_name = "Limited-Response SSRF - Truncated Response Body Disclosure"
            what_tested = "Instructed the server to fetch an internal endpoint that returns a partially truncated response body."
            what_happened = "The server returned a truncated fragment of internal data, indicating response length restriction or buffer clipping."
            why_matters = "Partial internal disclosures can still leak sensitive token fragments, session identifiers, and internal memory contents."
            human_evidence = "The server returned a partial fragment of internal data, showing response truncation occurred."

        elif probe_id == "LIMITED_GENERIC":
            vuln_name = "Limited-Response SSRF - Generic Execution Confirmation"
            what_tested = "Instructed the server to fetch an internal endpoint that responds with a generic success message."
            what_happened = "The server returned a generic success message distinct from the baseline 403 error response."
            why_matters = "Confirmation of internal request execution allows attackers to verify the existence of hidden internal endpoints."
            human_evidence = "The application returned a generic internal success message confirming that the internal endpoint executed."

        elif probe_id == "LIMITED_SUPPRESSED":
            vuln_name = "Limited-Response SSRF - Policy-Suppressed Content Indicator"
            what_tested = "Instructed the server to fetch an internal endpoint where content was filtered by a simulated policy filter."
            what_happened = "The server returned a response containing an active policy suppression indicator ([CONTENT_SUPPRESSED_BY_POLICY])."
            why_matters = "Policy filtering indicators confirm that internal requests reached the backend and that protective filters are applied downstream."
            human_evidence = "The response contained an explicit content suppression marker, confirming internal resource retrieval was intercepted."

        elif probe_id == "BLIND_OOB_CALLBACK" or "BLIND" in category or "OOB" in category:
            token = item.get("extra_metadata", {}).get("oob_token", "unique_token")
            vuln_name = "Blind Out-of-Band (OOB) SSRF - External Request Trigger"
            what_tested = f"Instructed the server to send a request to a dedicated local callback listener carrying tracking token '{token}'."
            what_happened = "The application initiated an outbound request to the callback listener on port 8090, which logged the matching token."
            why_matters = "When response content is hidden from the user, blind SSRF can still be used to trigger remote actions or attack other internal network services."
            human_evidence = f"An independent callback receiver on port 8090 captured an incoming request with the matching test token '{token}'."

        elif "TIME" in category:
            delta = item.get("extra_metadata", {}).get("delta_seconds", "N/A")
            vuln_name = "Time-Based SSRF - Differential Response Latency"
            what_tested = "Measured and compared server response times between an immediate baseline request and a 2-second delayed internal request."
            what_happened = f"The server took measurably longer to respond (delay delta: ~{delta}s), directly reflecting the internal endpoint's delay."
            why_matters = "Response time differences allow attackers to infer internal network state, scan for live internal hosts, and extract data bit-by-bit."
            human_evidence = f"The server exhibited a consistent, measurable delay (delta: {delta}s) when accessing the delayed internal resource."

        elif "BOOLEAN" in category:
            vuln_name = "Boolean-Based SSRF - Differential Conditional Evaluation"
            what_tested = "Evaluated differences in server response when requesting internal TRUE versus FALSE conditional endpoints."
            what_happened = "The server returned distinct HTTP status codes (200 vs 404) and different content lengths between TRUE and FALSE conditions."
            why_matters = "Conditional differences allow an attacker to perform Boolean-based blind data exfiltration by asking true/false queries."
            human_evidence = "The application returned clearly distinguishable responses (different status codes and byte lengths) based on internal condition evaluation."

        elif "NEGATIVE_CONTROL" in category:
            vuln_name = "Negative Control - Baseline Public Request"
            what_tested = "Instructed the server to fetch a normal public health check endpoint."
            what_happened = "The application processed the public endpoint without leaking internal metadata or triggering false positive indicators."
            why_matters = "Validates that the scanner does not falsely report normal application behavior as a vulnerability."
            human_evidence = "No internal markers or unauthorized metadata were exposed."

        return {
            "vulnerability_name": vuln_name,
            "what_was_tested": what_tested,
            "what_happened": what_happened,
            "why_this_matters": why_matters,
            "human_readable_summary": human_evidence
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
        inconclusive_tests = [f for f in findings if f.get("confidence") == "INCONCLUSIVE"]
        failed_tests = [f for f in findings if f.get("test_outcome") == "FAILED"]

        # Track per-technique statistics
        tech_counts = {
            "INBAND_SSRF": {"tests": 0, "positive": 0},
            "LIMITED_RESPONSE_SSRF": {"tests": 0, "positive": 0},
            "BLIND_OOB_SSRF": {"tests": 0, "positive": 0},
            "TIME_BASED_SSRF": {"tests": 0, "positive": 0},
            "BOOLEAN_BASED_SSRF": {"tests": 0, "positive": 0},
            "NEGATIVE_CONTROL": {"tests": 0, "positive": 0}
        }

        confidence_counts = {
            "LAB_CONFIRMED": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INCONCLUSIVE": 0
        }

        for item in findings:
            cat = item.get("vulnerability_category", "")
            if cat in tech_counts:
                tech_counts[cat]["tests"] += 1
                if item.get("detected"):
                    tech_counts[cat]["positive"] += 1

            conf = item.get("confidence", "")
            if item.get("detected") and conf in confidence_counts:
                confidence_counts[conf] += 1

        # Format individual detailed findings (for positive vulnerabilities)
        detailed_findings = []
        for index, item in enumerate(positive_tests, start=1):
            category = item.get("vulnerability_category", "UNKNOWN_SSRF")
            confidence = item.get("confidence", "MEDIUM")
            descriptions = self._generate_human_descriptions(item)
            tech_info = self.TECHNIQUE_METADATA.get(category, {
                "name": item.get("detection_technique", "SSRF Probing"),
                "remediation": "Restrict outgoing HTTP connections to an allowlist of approved destinations."
            })

            detailed_findings.append({
                "finding_id": f"SSRF-FINDING-{index:03d}",
                "vulnerability_name": descriptions["vulnerability_name"],
                "detection_technique": tech_info["name"],
                "affected_endpoint": item.get("endpoint", ""),
                "affected_parameter": item.get("parameter", ""),
                "http_method": item.get("method", "GET"),
                "test_result": "Detected",
                "confidence_level": confidence,
                "what_was_tested": descriptions["what_was_tested"],
                "what_happened": descriptions["what_happened"],
                "why_this_matters": descriptions["why_this_matters"],
                "evidence": {
                    "human_readable_summary": descriptions["human_readable_summary"],
                    "technical_evidence": item.get("evidence", []),
                    "verification_method": item.get("verification_method", "Direct Protocol Analysis"),
                    "http_status_code": item.get("http_status"),
                    "response_time_ms": item.get("response_time_ms")
                },
                "recommended_remediation": tech_info["remediation"]
            })

        # Build technique summary list
        techniques_summary = []
        for cat_key in ("INBAND_SSRF", "LIMITED_RESPONSE_SSRF", "BLIND_OOB_SSRF", "TIME_BASED_SSRF", "BOOLEAN_BASED_SSRF"):
            meta = self.TECHNIQUE_METADATA[cat_key]
            stats = tech_counts[cat_key]
            techniques_summary.append({
                "technique_name": meta["name"],
                "plain_english_description": meta["description"],
                "tests_performed": stats["tests"],
                "positive_findings": stats["positive"],
                "status": "VULNERABILITY_DETECTED" if stats["positive"] > 0 else "CLEAN"
            })

        # Executive summary narrative based on actual results
        if len(positive_tests) > 0:
            exec_summary_text = (
                "The automated security scan identified Server-Side Request Forgery (SSRF) behaviour in the target application's "
                "URL-fetching functionality. The application allowed the server to initiate requests to internal test resources "
                "and an independent local callback receiver using user-supplied URLs. These findings demonstrate that an attacker "
                "could leverage the server to bypass perimeter network controls and access internal services. "
                "All tests were conducted in a controlled local laboratory environment."
            )
            risk_level = "HIGH"
        else:
            exec_summary_text = (
                "The automated security scan did not detect any confirmed Server-Side Request Forgery (SSRF) behaviour in the "
                "target application during this assessment. The tested parameters did not permit unauthorized access to internal resources."
            )
            risk_level = "LOW"

        key_highlights = []
        if tech_counts["INBAND_SSRF"]["positive"] > 0:
            key_highlights.append(f"In-Band SSRF: {tech_counts['INBAND_SSRF']['positive']} probe(s) successfully retrieved internal secret data directly into responses.")
        if tech_counts["LIMITED_RESPONSE_SSRF"]["positive"] > 0:
            key_highlights.append(f"Limited-Response SSRF: {tech_counts['LIMITED_RESPONSE_SSRF']['positive']} probe(s) exposed internal state via status codes, custom headers, or filtered messages.")
        if tech_counts["BLIND_OOB_SSRF"]["positive"] > 0:
            key_highlights.append("Blind / Out-of-Band SSRF: Target initiated an outbound HTTP request verified by a local callback listener.")
        if tech_counts["TIME_BASED_SSRF"]["positive"] > 0:
            key_highlights.append("Time-Based SSRF: Measurable latency differences confirmed the server waited on internal delayed endpoints.")
        if tech_counts["BOOLEAN_BASED_SSRF"]["positive"] > 0:
            key_highlights.append("Boolean-Based SSRF: The server returned distinct responses for true and false internal conditions.")
        if not key_highlights:
            key_highlights.append("No active SSRF vulnerabilities identified.")

        # Test execution details (complete audit log of every test)
        test_execution_records = []
        for idx, item in enumerate(findings, start=1):
            cat = item.get("vulnerability_category", "")
            tech_name = self.TECHNIQUE_METADATA.get(cat, {}).get("name", item.get("detection_technique", "Unknown"))
            test_execution_records.append({
                "test_index": idx,
                "technique": tech_name,
                "endpoint": item.get("endpoint"),
                "parameter": item.get("parameter"),
                "payload": item.get("payload"),
                "outcome": item.get("test_outcome", "UNKNOWN"),
                "status_code": item.get("http_status"),
                "response_time_ms": item.get("response_time_ms"),
                "confidence": item.get("confidence"),
                "summary_evidence": item.get("evidence", [])[:2]
            })

        # Assemble the comprehensive report
        report = {
            "scan_overview": {
                "project_name": PROJECT_NAME,
                "scanner_version": VERSION,
                "scan_date_time": datetime.now(timezone.utc).isoformat(),
                "scan_duration_seconds": round(scan_duration_seconds, 2),
                "target_url": TARGET_URL,
                "scan_status": "COMPLETED",
                "total_endpoints_discovered": len(endpoints),
                "total_parameters_analysed": len(parameters),
                "total_tests_executed": total_tests,
                "positive_findings": len(positive_tests),
                "negative_tests": len(negative_tests),
                "inconclusive_tests": len(inconclusive_tests),
                "failed_tests": len(failed_tests)
            },
            "scan_summary": {
                "total_endpoints": len(endpoints),
                "total_parameters": len(parameters),
                "total_tests": total_tests,
                "positive_findings": len(positive_tests),
                "negative_tests": len(negative_tests),
                "inconclusive_tests": len(inconclusive_tests),
                "failed_tests": len(failed_tests),
                "scan_status": "COMPLETED"
            },
            "executive_summary": {
                "summary": exec_summary_text,
                "overall_risk_level": risk_level,
                "key_findings": key_highlights,
                "assessment_environment": "Controlled local test environment (loopback: 127.0.0.1)"
            },
            "detection_summary": {
                "techniques": techniques_summary,
                "confidence_breakdown": confidence_counts,
                "inband_findings": tech_counts["INBAND_SSRF"]["positive"],
                "limited_response_findings": tech_counts["LIMITED_RESPONSE_SSRF"]["positive"],
                "blind_oob_findings": tech_counts["BLIND_OOB_SSRF"]["positive"],
                "time_based_findings": tech_counts["TIME_BASED_SSRF"]["positive"],
                "boolean_based_findings": tech_counts["BOOLEAN_BASED_SSRF"]["positive"]
            },
            "detailed_findings": detailed_findings,
            "confidence_scale_reference": self.CONFIDENCE_SCALE,
            "technical_concepts_glossary": self.GLOSSARY,
            "recommendations": self.CONSOLIDATED_RECOMMENDATIONS,
            "test_execution_records": test_execution_records,
            "discovered_inventory": {
                "endpoints": endpoints,
                "parameters": parameters
            }
        }

        report_path = os.path.join(self.report_directory, "ssrf_report.json")

        with open(report_path, "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=4, ensure_ascii=False, default=str)

        print("\n[REPORT] JSON report generated successfully.")
        print(f"[REPORT] Location: {os.path.abspath(report_path)}")

        return report_path
