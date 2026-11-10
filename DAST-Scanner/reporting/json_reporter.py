import json
import os
from datetime import datetime, timezone
from config import PROJECT_NAME, VERSION, TARGET_URL


class JSONReporter:
    """
    Standards-compliant JSON vulnerability reporting system for SSRF Sentinel.
    Maintains clean separation between verified vulnerability findings, negative controls,
    and test execution records without introducing third-party formatting dependencies.
    """

    REMEDIATION_GUIDES = {
        "INBAND_SSRF": (
            "Enforce strict destination allowlists on the server-side HTTP client. "
            "Prevent the reflection of internal response bodies to callers. Implement network-level "
            "egress filtering blocking private/loopback IP address ranges (RFC 1918 / RFC 5735)."
        ),
        "LIMITED_RESPONSE_SSRF": (
            "Suppress downstream HTTP status codes, headers, and error fragments. "
            "Return standardized generic responses regardless of internal request outcome. "
            "Enforce egress filtering on server-side request forwarders."
        ),
        "BLIND_OOB_SSRF": (
            "Isolate backend request forwarders within a restricted network zone with default-deny "
            "egress rules. Enforce proxy authentication and block unauthorized outbound TCP/UDP traffic."
        ),
        "TIME_BASED_SSRF": (
            "Enforce aggressive socket connect and read timeouts (<= 2s) on internal HTTP requests. "
            "Decouple backend request execution from client HTTP lifecycles using asynchronous background workers."
        ),
        "BOOLEAN_BASED_SSRF": (
            "Normalize server-side application responses so conditional downstream queries do not produce "
            "measurable divergences in HTTP status codes, content lengths, or structural evaluation headers."
        )
    }

    def __init__(self):
        self.report_directory = "reports"
        os.makedirs(self.report_directory, exist_ok=True)

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

        # Technique breakdown
        detection_summary = {
            "inband_findings": 0,
            "limited_response_findings": 0,
            "blind_oob_findings": 0,
            "time_based_findings": 0,
            "boolean_based_findings": 0,
            "confidence_breakdown": {
                "LAB_CONFIRMED": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INCONCLUSIVE": 0
            }
        }

        # Format individual vulnerability findings
        formatted_findings = []
        for index, item in enumerate(positive_tests, start=1):
            category = item.get("vulnerability_category", "UNKNOWN_SSRF")
            confidence = item.get("confidence", "MEDIUM")

            # Update detection summary metrics
            if "INBAND" in category:
                detection_summary["inband_findings"] += 1
            elif "LIMITED" in category:
                detection_summary["limited_response_findings"] += 1
            elif "BLIND" in category or "OOB" in category:
                detection_summary["blind_oob_findings"] += 1
            elif "TIME" in category:
                detection_summary["time_based_findings"] += 1
            elif "BOOLEAN" in category:
                detection_summary["boolean_based_findings"] += 1

            if confidence in detection_summary["confidence_breakdown"]:
                detection_summary["confidence_breakdown"][confidence] += 1

            finding_record = {
                "finding_id": f"SSRF-VULN-{index:03d}",
                "vulnerability_category": category,
                "detection_technique": item.get("detection_technique", "SSRF Probing"),
                "endpoint": item.get("endpoint", ""),
                "parameter": item.get("parameter", ""),
                "http_method": item.get("method", "GET"),
                "test_identifier": item.get("extra_metadata", {}).get("probe_id", f"PROBE_{index}"),
                "payload": item.get("payload", ""),
                "http_status": item.get("http_status"),
                "response_time_ms": item.get("response_time_ms"),
                "confidence": confidence,
                "evidence": item.get("evidence", []),
                "verification_details": item.get("verification_method", "Direct Protocol Analysis"),
                "recommended_remediation": self.REMEDIATION_GUIDES.get(category, self.REMEDIATION_GUIDES["INBAND_SSRF"])
            }
            formatted_findings.append(finding_record)

        # Build execution log details for every test (positive, negative, inconclusive)
        test_execution_details = []
        for idx, item in enumerate(findings, start=1):
            test_execution_details.append({
                "test_index": idx,
                "technique": item.get("detection_technique"),
                "endpoint": item.get("endpoint"),
                "parameter": item.get("parameter"),
                "payload": item.get("payload"),
                "outcome": item.get("test_outcome", "UNKNOWN"),
                "status_code": item.get("http_status"),
                "response_time_ms": item.get("response_time_ms"),
                "confidence": item.get("confidence"),
                "summary_evidence": item.get("evidence", [])[:2]
            })

        # Assemble full final report
        report = {
            "scan_metadata": {
                "project": PROJECT_NAME,
                "scanner_version": VERSION,
                "target_url": TARGET_URL,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "scan_duration_seconds": round(scan_duration_seconds, 2),
                "report_format": "JSON",
                "scanner_architecture": "Multi-Engine Evidence-Based DAST"
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
            "detection_summary": detection_summary,
            "individual_findings": formatted_findings,
            "discovered_endpoints": endpoints,
            "analyzed_parameters": parameters,
            "test_execution_details": test_execution_details
        }

        report_path = os.path.join(self.report_directory, "ssrf_report.json")

        with open(report_path, "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=4, ensure_ascii=False, default=str)

        print("\n[REPORT] JSON report generated successfully.")
        print(f"[REPORT] Location: {os.path.abspath(report_path)}")

        return report_path
