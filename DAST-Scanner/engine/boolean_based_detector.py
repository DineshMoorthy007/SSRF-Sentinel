import time
from typing import List, Dict, Any
from config import (
    BOOLEAN_TEST_ITERATIONS,
    BOOLEAN_LENGTH_DIFF_THRESHOLD,
    SCAN_DELAY,
    BOOLEAN_TRUE_MARKER
)
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer


class BooleanBasedDetector:
    """
    Detection engine for Boolean-Based SSRF.
    Compares differential HTTP behavior (status codes, body byte-length, headers, evaluation text)
    between logical TRUE and FALSE server-side queries across multiple test cycles to prevent false positives.
    """

    def __init__(self, client, response_analyzer=None, payload_generator=None):
        self.client = client
        self.response_analyzer = response_analyzer or ResponseAnalyzer()
        self.payload_generator = payload_generator or PayloadGenerator()
        self.iterations = BOOLEAN_TEST_ITERATIONS
        self.min_length_diff = BOOLEAN_LENGTH_DIFF_THRESHOLD

    def scan(self, endpoint: str, parameter: str, mode: str = "vulnerable") -> List[Dict[str, Any]]:
        findings = []
        is_secure_mode = (mode == "secure")
        probes = self.payload_generator.generate_category_h()
        true_probe = probes["true_probe"]
        false_probe = probes["false_probe"]

        print(f"\n  [BOOLEAN-BASED] Testing condition pairs across {self.iterations} validation cycle(s) (Mode: {mode.upper()})...")

        true_responses = []
        false_responses = []

        for cycle in range(self.iterations):
            params_true = {parameter: true_probe["payload"]}
            params_false = {parameter: false_probe["payload"]}
            if is_secure_mode:
                params_true["mode"] = "secure"
                params_false["mode"] = "secure"

            # Probe TRUE condition
            r_true = self.client.get(endpoint, params=params_true)
            true_responses.append(self.response_analyzer.extract_metrics(r_true))
            time.sleep(SCAN_DELAY)

            # Probe FALSE condition
            r_false = self.client.get(endpoint, params=params_false)
            false_responses.append(self.response_analyzer.extract_metrics(r_false))
            time.sleep(SCAN_DELAY)

        last_true = true_responses[-1]
        last_false = false_responses[-1]

        status_true = last_true["status_code"]
        status_false = last_false["status_code"]
        len_true = last_true["length"]
        len_false = last_false["length"]
        len_diff = abs(len_true - len_false)

        eval_header_true = last_true["headers"].get("X-SSRF-Evaluation", "")
        eval_header_false = last_false["headers"].get("X-SSRF-Evaluation", "")

        is_detected = False
        confidence = "NONE"
        evidence = []
        verification_method = "Differential Boolean Inference"
        test_outcome = "NEGATIVE"

        if is_secure_mode:
            # Both conditions must be blocked with HTTP 403 in secure mode
            if status_true == 403 and status_false == 403:
                evidence.append("Defense Verified: Boolean condition probes blocked with HTTP 403 in secure mode.")
                confidence = "LAB_CONFIRMED"
                test_outcome = "DEFENSE_VERIFIED"
                verification_method = "Defensive Control Verification"
            else:
                evidence.append(f"Unexpected statuses in secure mode: TRUE={status_true}, FALSE={status_false}")
                test_outcome = "INCONCLUSIVE"
        else:
            has_true_marker = BOOLEAN_TRUE_MARKER in last_true["body"]
            status_divergence = (status_true is not None and status_false is not None and status_true != status_false)
            length_divergence = (len_diff >= self.min_length_diff)
            header_divergence = (eval_header_true != eval_header_false and (eval_header_true or eval_header_false))

            evidence.append(
                f"TRUE: HTTP {status_true} ({len_true} bytes) | "
                f"FALSE: HTTP {status_false} ({len_false} bytes) | "
                f"Length Delta: {len_diff} bytes"
            )

            if has_true_marker and status_divergence:
                is_detected = True
                confidence = "LAB_CONFIRMED"
                evidence.append(f"Boolean verification marker '{BOOLEAN_TRUE_MARKER}' matched with divergent status ({status_true} vs {status_false}).")
                verification_method = "Cryptographic Boolean Marker & Status Inference"
                test_outcome = "POSITIVE"
                print(f"    [+] DETECTED: Boolean SSRF (Marker Verified, {status_true} vs {status_false})")
            elif status_divergence and length_divergence:
                is_detected = True
                confidence = "HIGH"
                evidence.append(
                    f"Consistent status divergence ({status_true} vs {status_false}) "
                    f"and significant length delta ({len_diff} bytes) across {self.iterations} validation cycle(s)."
                )
                test_outcome = "POSITIVE"
                print(f"    [+] DETECTED: Boolean SSRF (Status {status_true} vs {status_false}, Delta {len_diff}B)")
            elif header_divergence or status_divergence:
                is_detected = True
                confidence = "MEDIUM"
                test_outcome = "POSITIVE"
                evidence.append("Partial boolean differential indicators detected.")
                print(f"    [!] DETECTED (Partial): Boolean SSRF")
            else:
                test_outcome = "NEGATIVE"
                print(f"    [-] Clean: No boolean differential observed.")

        finding = self.response_analyzer.create_finding(
            category="BOOLEAN_BASED_SSRF",
            technique="Boolean-Based",
            endpoint=endpoint,
            parameter=parameter,
            payload=true_probe["payload"],
            response=None,
            detected=is_detected,
            confidence=confidence,
            evidence=evidence,
            verification_method=verification_method,
            extra_metadata={
                "status_true": status_true,
                "status_false": status_false,
                "length_true": len_true,
                "length_false": len_false,
                "length_diff": len_diff,
                "probe_id": true_probe["id"],
                "test_outcome": test_outcome,
                "mode": mode
            }
        )

        findings.append(finding)
        return findings
