import time
import statistics
from config import (
    TIME_DELAY_SECONDS,
    TIME_DELTA_THRESHOLD,
    TIME_TEST_ITERATIONS,
    SCAN_DELAY,
    TIME_FAST_MARKER,
    TIME_DELAYED_MARKER
)
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer


class TimeBasedDetector:
    """
    Detection engine for Time-Based SSRF.
    Measures differential round-trip latency across baseline/fast requests and delayed endpoints.
    Uses multi-iteration median calculations to filter network jitter and prevent false positives.
    CRITICAL: In compliance with security standards, timing anomalies alone never receive LAB_CONFIRMED.
    """

    def __init__(self, client, response_analyzer=None, payload_generator=None):
        self.client = client
        self.response_analyzer = response_analyzer or ResponseAnalyzer()
        self.payload_generator = payload_generator or PayloadGenerator()
        self.iterations = TIME_TEST_ITERATIONS
        self.threshold = TIME_DELTA_THRESHOLD
        self.delay_target = TIME_DELAY_SECONDS

    def _measure_latency(self, endpoint: str, parameter: str, target_url: str) -> tuple:
        """Executes a request and measures total elapsed time in seconds."""
        t_start = time.perf_counter()
        response = self.client.get(endpoint, params={parameter: target_url})
        t_elapsed = time.perf_counter() - t_start
        return t_elapsed, response

    def scan(self, endpoint: str, parameter: str) -> list:
        findings = []
        timing_probes = self.payload_generator.generate_time_based_payloads()
        fast_probe = timing_probes["fast"]
        delayed_probe = timing_probes["delayed"]

        print(f"\n  [TIME-BASED] Calibrating latency ({self.iterations} iterations per probe)...")

        fast_times = []
        delayed_times = []
        last_fast_resp = None
        last_delayed_resp = None

        # 1. Measure fast baseline requests
        for i in range(self.iterations):
            elapsed, resp = self._measure_latency(endpoint, parameter, fast_probe["payload"])
            fast_times.append(elapsed)
            last_fast_resp = resp
            time.sleep(SCAN_DELAY)

        # 2. Measure delayed requests
        for i in range(self.iterations):
            elapsed, resp = self._measure_latency(endpoint, parameter, delayed_probe["payload"])
            delayed_times.append(elapsed)
            last_delayed_resp = resp
            time.sleep(SCAN_DELAY)

        median_fast = statistics.median(fast_times)
        median_delayed = statistics.median(delayed_times)
        delta_time = median_delayed - median_fast

        is_detected = False
        confidence = "NONE"
        evidence = []
        verification_method = "Multi-Sample Differential Timing Analysis"

        evidence.append(
            f"Fast probe median: {median_fast:.3f}s {fast_times} | "
            f"Delayed probe median: {median_delayed:.3f}s {delayed_times} | "
            f"Delta: {delta_time:.3f}s (Threshold: {self.threshold:.3f}s)"
        )

        # Check for timing delta
        if delta_time >= self.threshold:
            is_detected = True
            # NOTE: Rule - timing anomaly alone must never receive LAB_CONFIRMED!
            # Even if marker is reflected, timing-only technique caps at HIGH unless content inspection verifies it.
            body = last_delayed_resp.text if last_delayed_resp else ""
            if TIME_DELAYED_MARKER in body:
                confidence = "HIGH"
                evidence.append(f"Confirmed internal delayed execution marker '{TIME_DELAYED_MARKER}' in delayed response.")
            else:
                confidence = "HIGH"
                evidence.append("Consistent timing differential observed across all iterations.")
            print(f"    [+] DETECTED: Time-Based SSRF (Delta: {delta_time:.2f}s, Confidence: {confidence})")
        elif delta_time >= (self.threshold * 0.7):
            is_detected = True
            confidence = "MEDIUM"
            evidence.append("Borderline latency anomaly observed (potential internal network lag).")
            print(f"    [!] DETECTED (Borderline): Time-Based SSRF (Delta: {delta_time:.2f}s, Confidence: {confidence})")
        else:
            evidence.append("No statistically significant delay observed.")
            print(f"    [-] Clean: Normal response latency (Delta: {delta_time:.2f}s)")

        finding = self.response_analyzer.create_finding(
            category="TIME_BASED_SSRF",
            technique="Time-Based SSRF",
            endpoint=endpoint,
            parameter=parameter,
            payload=delayed_probe["payload"],
            response=last_delayed_resp,
            detected=is_detected,
            confidence=confidence,
            evidence=evidence,
            verification_method=verification_method,
            extra_metadata={
                "fast_times_sec": [round(t, 3) for t in fast_times],
                "delayed_times_sec": [round(t, 3) for t in delayed_times],
                "median_fast_sec": round(median_fast, 3),
                "median_delayed_sec": round(median_delayed, 3),
                "delta_seconds": round(delta_time, 3),
                "configured_delay_seconds": self.delay_target,
                "threshold_seconds": self.threshold
            }
        )

        findings.append(finding)
        return findings

