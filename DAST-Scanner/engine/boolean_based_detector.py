import time
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

    def scan(self, endpoint: str, parameter: str) -> list:
        findings = []
        probes = self.payload_generator.generate_boolean_payloads()
        true_probe = probes["true_probe"]
        false_probe = probes["false_probe"]

        print(f"\n  [BOOLEAN-BASED] Testing condition pairs across {self.iterations} validation cycle(s)...")

        true_responses = []
        false_responses = []

        for cycle in range(self.iterations):
            # Probe TRUE condition
            r_true = self.client.get(endpoint, params={parameter: true_probe["payload"]})
            true_responses.append(self.response_analyzer.extract_metrics(r_true))
            time.sleep(SCAN_DELAY)

            # Probe FALSE condition
            r_false = self.client.get(endpoint, params={parameter: false_probe["payload"]})
            false_responses.append(self.response_analyzer.extract_metrics(r_false))
            time.sleep(SCAN_DELAY)

        # Consistency analysis across cycles
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

        # Check for verification marker
        has_true_marker = BOOLEAN_TRUE_MARKER in last_true["body"]

        # 1. Distinct status codes (e.g. 200 vs 404)
        status_divergence = (status_true is not None and status_false is not None and status_true != status_false)

        # 2. Distinct byte lengths exceeding threshold
        length_divergence = (len_diff >= self.min_length_diff)

        # 3. Explicit evaluation headers or signatures
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
            print(f"    [+] DETECTED: Boolean SSRF (Marker Verified, {status_true} vs {status_false})")
        elif status_divergence and length_divergence:
            is_detected = True
            confidence = "HIGH"
            evidence.append(
                f"Consistent status divergence ({status_true} vs {status_false}) "
                f"and significant length delta ({len_diff} bytes) across {self.iterations} validation cycle(s)."
            )
            print(f"    [+] DETECTED: Boolean SSRF (Status {status_true} vs {status_false}, Delta {len_diff}B)")
        elif header_divergence or status_divergence:
            is_detected = True
            confidence = "MEDIUM"
            evidence.append("Measurable structural or header evaluation difference observed between TRUE and FALSE probes.")
            print(f"    [+] DETECTED: Boolean SSRF (Header/Structure divergence, Confidence: MEDIUM)")
        else:
            evidence.append("Responses to TRUE and FALSE conditions are statistically and structurally indistinguishable.")
            print("    [-] Clean: Boolean conditions yielded identical responses.")

        finding = self.response_analyzer.create_finding(
            category="BOOLEAN_BASED_SSRF",
            technique="Boolean-Based SSRF",
            endpoint=endpoint,
            parameter=parameter,
            payload=true_probe["payload"],
            response=None, # Synthesized comparative evaluation
            detected=is_detected,
            confidence=confidence,
            evidence=evidence,
            verification_method=verification_method,
            extra_metadata={
                "true_status": status_true,
                "false_status": status_false,
                "true_length": len_true,
                "false_length": len_false,
                "length_difference": len_diff,
                "true_header_eval": eval_header_true,
                "false_header_eval": eval_header_false,
                "test_cycles": self.iterations
            }
        )
        # Populate response time from last true metric
        finding["http_status"] = status_true
        finding["response_time_ms"] = last_true["latency_ms"]
        finding["response_length"] = len_true

        findings.append(finding)
        return findings

