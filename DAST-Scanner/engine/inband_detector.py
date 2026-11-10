import time
from config import SCAN_DELAY
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer


class InBandDetector:
    """
    Detection engine for In-Band / Content-Based SSRF.
    Identifies full internal resource disclosures, sensitive configuration leaks,
    custom headers, and known verification markers reflected through public endpoints.
    """

    def __init__(self, client, response_analyzer=None, payload_generator=None):
        self.client = client
        self.response_analyzer = response_analyzer or ResponseAnalyzer()
        self.payload_generator = payload_generator or PayloadGenerator()

    def scan(self, endpoint: str, parameter: str) -> list:
        findings = []
        payloads = self.payload_generator.generate_inband_payloads()

        print(f"\n  [IN-BAND] Testing parameter '{parameter}' across {len(payloads)} content probes...")

        for probe in payloads:
            target_url = probe["payload"]
            probe_name = probe["name"]
            expected_marker = probe["expected"].get("marker")

            response = self.client.get(
                endpoint,
                params={parameter: target_url}
            )

            metrics = self.response_analyzer.extract_metrics(response)
            eval_result = self.response_analyzer.inspect_inband(metrics, expected_marker)

            is_detected = eval_result["detected"]
            confidence = eval_result["confidence"]
            evidence = eval_result["evidence"]
            verification_method = eval_result["verification_method"]

            if is_detected:
                evidence.append(f"Probe '{probe_name}' reflected internal resource content.")
                print(f"    [+] DETECTED: {probe_name} ({confidence})")
            else:
                print(f"    [-] Clean: {probe_name}")

            finding = self.response_analyzer.create_finding(
                category="INBAND_SSRF",
                technique="In-Band / Content-Based SSRF",
                endpoint=endpoint,
                parameter=parameter,
                payload=target_url,
                response=response,
                detected=is_detected,
                confidence=confidence,
                evidence=evidence,
                verification_method=verification_method,
                extra_metadata={
                    "probe_id": probe["id"],
                    "probe_name": probe_name,
                    "expected_marker": expected_marker
                }
            )

            findings.append(finding)
            time.sleep(SCAN_DELAY)

        return findings

