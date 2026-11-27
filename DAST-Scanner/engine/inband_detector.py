import time
from typing import List, Dict, Any
from config import SCAN_DELAY, VERIFICATION_MARKER, INBAND_MARKER, REDIRECT_MARKER
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer


class InBandDetector:
    """
    Detection engine for In-Band / Content-Based SSRF.
    Evaluates:
    - Category A: Standard internal URL endpoints
    - Category B: Alternative local address representations (decimal, octal, hex, shorthand, IPv6)
    - Category C: URL encoding and normalization variations
    - Category D: Redirect-based inputs
    - Category E: Malformed URL and unsupported scheme controls
    """

    def __init__(self, client, response_analyzer=None, payload_generator=None):
        self.client = client
        self.response_analyzer = response_analyzer or ResponseAnalyzer()
        self.payload_generator = payload_generator or PayloadGenerator()

    def scan(self, endpoint: str, parameter: str, mode: str = "vulnerable") -> List[Dict[str, Any]]:
        findings = []
        is_secure_mode = (mode == "secure")

        # Gather test probes across relevant categories
        probes = []
        probes.extend(self.payload_generator.generate_category_a())
        probes.extend(self.payload_generator.generate_category_b())
        probes.extend(self.payload_generator.generate_category_c())
        probes.extend(self.payload_generator.generate_category_d())

        print(f"\n  [IN-BAND] Probing '{parameter}' across {len(probes)} content/bypass/redirect probes (Mode: {mode.upper()})...")

        for probe in probes:
            probe_id = probe["id"]
            probe_name = probe["name"]
            probe_cat = probe["category"]
            target_url = probe["payload"]
            expected = probe.get("expected", {})
            expected_marker = expected.get("marker")

            params = {parameter: target_url}
            if is_secure_mode:
                params["mode"] = "secure"

            response = self.client.get(endpoint, params=params)
            metrics = self.response_analyzer.extract_metrics(response)
            status_code = metrics["status_code"]
            body = metrics["body"]

            is_detected = False
            confidence = "NONE"
            evidence = []
            verification_method = "Cryptographic Marker & Content Verification"

            if is_secure_mode:
                # In SECURE MODE: Target is expected to block access with HTTP 403
                expected_secure_status = probe.get("secure_expected_status", 403)
                if status_code == 403:
                    # Defensive success: Correctly blocked by application policy
                    evidence.append(f"Defense Verified: Prohibited request correctly blocked with HTTP 403 (Mode: Secure).")
                    if "ERR_INTERNAL_PORT_BLOCKED" in body:
                        evidence.append("Security rule verified: Port 8081 internal service restriction active.")
                    elif "ERR_NON_CANONICAL_HOST" in body:
                        evidence.append("Security rule verified: Non-canonical host notation rejected.")
                    elif "ERR_REDIRECT_RESTRICTED" in body:
                        evidence.append("Security rule verified: Redirect to internal resource restricted.")
                    verification_method = "Defensive Control Verification"
                    confidence = "LAB_CONFIRMED"
                    test_outcome = "DEFENSE_VERIFIED"
                elif status_code == 200 and (VERIFICATION_MARKER in body or INBAND_MARKER in body):
                    # Unexpected leak in secure mode: CRITICAL BYPASS!
                    is_detected = True
                    confidence = "LAB_CONFIRMED"
                    evidence.append(f"SECURITY BYPASS: Target in secure mode failed to block request! Internal marker exposed.")
                    test_outcome = "SECURITY_FAILURE"
                    verification_method = "Defense Bypass Detection"
                else:
                    test_outcome = "INCONCLUSIVE"
                    evidence.append(f"Unexpected status in secure mode: HTTP {status_code}")
            else:
                # In VULNERABLE MODE: Evaluate internal exposure
                eval_result = self.response_analyzer.inspect_inband(metrics, expected_marker)
                is_detected = eval_result["detected"]
                confidence = eval_result["confidence"]
                evidence.extend(eval_result["evidence"])
                verification_method = eval_result["verification_method"]

                if is_detected:
                    evidence.append(f"Probe '{probe_name}' ({probe_id}) accessed internal resource via parameter '{parameter}'.")
                    test_outcome = "POSITIVE"
                    print(f"    [+] DETECTED: {probe_name} [{confidence}]")
                else:
                    test_outcome = "NEGATIVE"
                    print(f"    [-] Clean: {probe_name}")

            finding = self.response_analyzer.create_finding(
                category="INBAND_SSRF",
                technique="In-Band / Content-Based",
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
                    "category": probe_cat,
                    "test_outcome": test_outcome,
                    "mode": mode
                }
            )
            findings.append(finding)
            time.sleep(SCAN_DELAY)

        return findings
