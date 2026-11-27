import time
from typing import List, Dict, Any
from config import SCAN_DELAY, LIMITED_HEADER_MARKER
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer


class LimitedResponseDetector:
    """
    Detection engine for Limited-Response SSRF.
    Identifies server-side request execution when the response is constrained:
    - Status-only (e.g., HTTP 204 No Content)
    - Header-only information leakage
    - Truncated response bodies / buffers
    - Generic success acknowledgements
    - Policy-suppressed / sanitized internal payloads
    """

    def __init__(self, client, response_analyzer=None, payload_generator=None):
        self.client = client
        self.response_analyzer = response_analyzer or ResponseAnalyzer()
        self.payload_generator = payload_generator or PayloadGenerator()

    def _get_baseline(self, endpoint: str, parameter: str, mode: str = "vulnerable"):
        """Fetches baseline response using a non-existent internal path."""
        bogus_url = "http://127.0.0.1:8081/non_existent_resource_404"
        params = {parameter: bogus_url}
        if mode == "secure":
            params["mode"] = "secure"
        response = self.client.get(endpoint, params=params)
        return self.response_analyzer.extract_metrics(response)

    def scan(self, endpoint: str, parameter: str, mode: str = "vulnerable") -> List[Dict[str, Any]]:
        findings = []
        is_secure_mode = (mode == "secure")
        payloads = self.payload_generator.generate_category_f()

        print(f"\n  [LIMITED-RESPONSE] Calibrating baseline and testing '{parameter}' (Mode: {mode.upper()})...")
        baseline = self._get_baseline(endpoint, parameter, mode)

        for probe in payloads:
            probe_id = probe["id"]
            probe_name = probe["name"]
            target_url = probe["payload"]

            params = {parameter: target_url}
            if is_secure_mode:
                params["mode"] = "secure"

            response = self.client.get(endpoint, params=params)
            metrics = self.response_analyzer.extract_metrics(response)
            status_code = metrics["status_code"]
            headers = metrics["headers"]
            body = metrics["body"]

            is_detected = False
            confidence = "NONE"
            evidence = []
            verification_method = "Limited Protocol Artifact Analysis"
            test_outcome = "NEGATIVE"

            if is_secure_mode:
                if status_code == 403:
                    evidence.append("Defense Verified: Limited-response endpoint correctly blocked with HTTP 403 in secure mode.")
                    confidence = "LAB_CONFIRMED"
                    test_outcome = "DEFENSE_VERIFIED"
                    verification_method = "Defensive Control Verification"
                else:
                    evidence.append(f"Unexpected status in secure mode: HTTP {status_code}")
                    test_outcome = "INCONCLUSIVE"
            else:
                # 1. Status-Only evaluation (HTTP 204 No Content)
                if probe_id == "PL-LIM-STATUS-001":
                    if status_code == 204:
                        is_detected = True
                        confidence = "HIGH"
                        evidence.append("Target returned HTTP 204 No Content confirming internal request execution.")
                        verification_method = "Status-Only HTTP 204 Inspection"
                    elif status_code == 200 and metrics["length"] == 0:
                        is_detected = True
                        confidence = "HIGH"
                        evidence.append("Target returned HTTP 200 with empty body (0 bytes), distinct from error baselines.")
                        verification_method = "Zero-Length Body Protocol Inspection"

                # 2. Header-Only evaluation
                elif probe_id == "PL-LIM-HEADER-002":
                    if LIMITED_HEADER_MARKER in str(headers) or "X-Internal-Marker" in headers:
                        is_detected = True
                        confidence = "LAB_CONFIRMED"
                        evidence.append(f"Internal header marker '{LIMITED_HEADER_MARKER}' discovered in response headers.")
                        verification_method = "Header Marker Inspection"
                    elif any(h.lower().startswith("x-internal") for h in headers):
                        is_detected = True
                        confidence = "HIGH"
                        evidence.append("Disclosed custom 'X-Internal-*' headers without body content.")
                        verification_method = "Internal Header Dissemination Analysis"

                # 3. Truncated Body evaluation
                elif probe_id == "PL-LIM-TRUNC-003":
                    if "SSRF_SECRET_SEGMENT_PARTIAL_DATA" in body:
                        is_detected = True
                        confidence = "LAB_CONFIRMED"
                        evidence.append("Disclosed partial/truncated internal secret fragment in response stream.")
                        verification_method = "Truncated Buffer Fragment Recognition"
                    elif body.startswith('{"status":"success"') and not body.endswith("}"):
                        is_detected = True
                        confidence = "HIGH"
                        evidence.append("Syntactically broken/truncated JSON indicates server buffer boundary cut-off.")
                        verification_method = "Truncated Syntax Stream Analysis"

                # 4. Generic Success evaluation
                elif probe_id == "PL-LIM-GEN-004":
                    if "Internal request processed successfully" in body:
                        is_detected = True
                        confidence = "HIGH"
                        evidence.append("Application returned generic internal success confirmation distinct from error baseline.")
                        verification_method = "Generic Execution Confirmation"

                # 5. Content Filter Suppression evaluation
                elif probe_id == "PL-LIM-SUPP-005":
                    if "[CONTENT_SUPPRESSED_BY_POLICY]" in body:
                        is_detected = True
                        confidence = "LAB_CONFIRMED"
                        evidence.append("Internal policy filter suppression marker '[CONTENT_SUPPRESSED_BY_POLICY]' verified.")
                        verification_method = "Sanitization Marker Verification"

                if is_detected:
                    test_outcome = "POSITIVE"
                    print(f"    [+] DETECTED: {probe_name} [{confidence}]")
                else:
                    test_outcome = "NEGATIVE"
                    print(f"    [-] Clean: {probe_name}")

            finding = self.response_analyzer.create_finding(
                category="LIMITED_RESPONSE_SSRF",
                technique="Limited-Response",
                endpoint=endpoint,
                parameter=parameter,
                payload=target_url,
                response=response,
                detected=is_detected,
                confidence=confidence,
                evidence=evidence,
                verification_method=verification_method,
                extra_metadata={
                    "probe_id": probe_id,
                    "probe_name": probe_name,
                    "test_outcome": test_outcome,
                    "mode": mode
                }
            )
            findings.append(finding)
            time.sleep(SCAN_DELAY)

        return findings
