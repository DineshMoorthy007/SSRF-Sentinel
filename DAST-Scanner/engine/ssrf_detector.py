from engine.response_analyzer import ResponseAnalyzer
from engine.payload_generator import PayloadGenerator
from engine.inband_detector import InBandDetector
from engine.limited_response_detector import LimitedResponseDetector
from engine.blind_oob_detector import BlindOOBDetector
from engine.time_based_detector import TimeBasedDetector
from engine.boolean_based_detector import BooleanBasedDetector


class SSRFDetector:
    """
    Unified Detection Coordinator for SSRF Sentinel.
    Orchestrates the five specialized detection engines across identified candidate parameters:
    1. In-Band / Content-Based SSRF
    2. Limited-Response SSRF
    3. Blind / Out-of-Band (OOB) SSRF
    4. Time-Based SSRF
    5. Boolean-Based SSRF
    """

    def __init__(self, client):
        self.client = client
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()

        # Initialize independent detection engines
        self.inband_detector = InBandDetector(
            self.client,
            self.response_analyzer,
            self.payload_generator
        )
        self.limited_detector = LimitedResponseDetector(
            self.client,
            self.response_analyzer,
            self.payload_generator
        )
        self.blind_detector = BlindOOBDetector(
            self.client,
            self.response_analyzer,
            self.payload_generator
        )
        self.time_detector = TimeBasedDetector(
            self.client,
            self.response_analyzer,
            self.payload_generator
        )
        self.boolean_detector = BooleanBasedDetector(
            self.client,
            self.response_analyzer,
            self.payload_generator
        )

        self.findings = []

    def _create_error_finding(self, category: str, technique: str, endpoint: str, parameter: str, error: Exception) -> dict:
        """Constructs an error/failure finding when a detector throws an unhandled exception."""
        return {
            "vulnerability_category": category,
            "detection_technique": technique,
            "endpoint": endpoint,
            "parameter": parameter,
            "payload": "N/A",
            "http_status": None,
            "response_time_ms": None,
            "response_length": 0,
            "detected": False,
            "confidence": "INCONCLUSIVE",
            "evidence": [f"Detector encountered unexpected error during probing: {str(error)}"],
            "verification_method": "Error Capture Handler",
            "test_outcome": "FAILED",
            "extra_metadata": {"error_type": type(error).__name__}
        }

    def _run_negative_controls(self, endpoint: str, parameter: str) -> list:
        """Executes negative control calibration probes to verify false-positive immunity."""
        ctrl_probes = self.payload_generator.generate_control_payloads()
        findings = []
        for probe in ctrl_probes:
            response = self.client.get(endpoint, params={parameter: probe["payload"]})
            metrics = self.response_analyzer.extract_metrics(response)
            eval_result = self.response_analyzer.inspect_inband(metrics)
            is_detected = eval_result["detected"]

            findings.append(self.response_analyzer.create_finding(
                category="NEGATIVE_CONTROL",
                technique="Negative Control Calibration",
                endpoint=endpoint,
                parameter=parameter,
                payload=probe["payload"],
                response=response,
                detected=is_detected,
                confidence="NONE" if not is_detected else "HIGH",
                evidence=["Negative control verified: no internal data or markers exposed."] if not is_detected else ["False positive: Negative control triggered unexpected SSRF detection."],
                verification_method="Negative Control Invariance Check",
                extra_metadata={"probe_id": probe["id"]}
            ))
        return findings

    def _normalize_and_deduplicate(self, raw_findings: list) -> list:
        """Normalizes and deduplicates findings while preserving complete evidence traces."""
        normalized = []
        seen = set()

        for f in raw_findings:
            # Create a signature based on endpoint, parameter, technique, and payload
            sig = (
                f.get("endpoint"),
                f.get("parameter"),
                f.get("detection_technique"),
                f.get("payload")
            )
            if sig not in seen:
                seen.add(sig)
                normalized.append(f)

        return normalized

    def scan(self, parameters: list) -> list:
        print("\n" + "=" * 65)
        print("          STARTING MULTI-ENGINE SSRF DETECTION")
        print("=" * 65)

        self.findings = []
        candidates = [p for p in parameters if p.get("ssrf_candidate")]

        if not candidates:
            print("[WARNING] No viable SSRF candidate parameters identified.")
            return []

        for candidate in candidates:
            endpoint = candidate["endpoint"]
            parameter_name = candidate["parameter"]
            method = candidate.get("method", "GET")

            if method != "GET":
                print(f"[SKIP] Unsupported method for SSRF probing: {method}")
                continue

            print(f"\n[TARGET] Probing Endpoint: {endpoint} | Parameter: '{parameter_name}' (Priority: {candidate.get('priority', 'HIGH')})")

            # 1. In-Band / Content-Based SSRF Detection
            try:
                inband_findings = self.inband_detector.scan(endpoint, parameter_name)
                self.findings.extend(inband_findings)
            except Exception as err:
                print(f"  [ERROR] In-Band detector error: {err}")
                self.findings.append(self._create_error_finding("INBAND_SSRF", "In-Band / Content-Based SSRF", endpoint, parameter_name, err))

            # 2. Limited-Response SSRF Detection
            try:
                limited_findings = self.limited_detector.scan(endpoint, parameter_name)
                self.findings.extend(limited_findings)
            except Exception as err:
                print(f"  [ERROR] Limited-Response detector error: {err}")
                self.findings.append(self._create_error_finding("LIMITED_RESPONSE_SSRF", "Limited-Response SSRF", endpoint, parameter_name, err))

            # 3. Blind / Out-of-Band SSRF Detection
            try:
                blind_findings = self.blind_detector.scan(endpoint, parameter_name)
                self.findings.extend(blind_findings)
            except Exception as err:
                print(f"  [ERROR] Blind OOB detector error: {err}")
                self.findings.append(self._create_error_finding("BLIND_OOB_SSRF", "Blind / Out-of-Band SSRF", endpoint, parameter_name, err))

            # 4. Time-Based SSRF Detection
            try:
                time_findings = self.time_detector.scan(endpoint, parameter_name)
                self.findings.extend(time_findings)
            except Exception as err:
                print(f"  [ERROR] Time-Based detector error: {err}")
                self.findings.append(self._create_error_finding("TIME_BASED_SSRF", "Time-Based SSRF", endpoint, parameter_name, err))

            # 5. Boolean-Based SSRF Detection
            try:
                boolean_findings = self.boolean_detector.scan(endpoint, parameter_name)
                self.findings.extend(boolean_findings)
            except Exception as err:
                print(f"  [ERROR] Boolean-Based detector error: {err}")
                self.findings.append(self._create_error_finding("BOOLEAN_BASED_SSRF", "Boolean-Based SSRF", endpoint, parameter_name, err))

            # 6. Negative Control Calibration Probe
            try:
                ctrl_findings = self._run_negative_controls(endpoint, parameter_name)
                self.findings.extend(ctrl_findings)
            except Exception as err:
                print(f"  [ERROR] Negative control calibration error: {err}")

        self.findings = self._normalize_and_deduplicate(self.findings)

        print("\n[INFO] Multi-Engine SSRF detection completed.")
        return self.findings

    def display_results(self):
        print("\n" + "=" * 70)
        print("               SSRF SENTINEL - DETECTION SUMMARY")
        print("=" * 70)

        confirmed = [f for f in self.findings if f.get("detected")]

        if not confirmed:
            print("[INFO] No positive SSRF vulnerabilities confirmed during this scan.")
        else:
            for i, f in enumerate(confirmed, 1):
                print(f"\n[{i}] VULNERABILITY CONFIRMED: {f.get('detection_technique')}")
                print(f"    Category   : {f.get('vulnerability_category')}")
                print(f"    Endpoint   : {f.get('endpoint')}")
                print(f"    Parameter  : {f.get('parameter')}")
                print(f"    Payload    : {f.get('payload')}")
                print(f"    Confidence : {f.get('confidence')}")
                print(f"    Method     : {f.get('verification_method')}")
                evidence = f.get("evidence", [])
                for ev in evidence:
                    print(f"    - Evidence : {ev}")

        print("\n" + "-" * 70)
        print(f" Total Tests Run : {len(self.findings)}")
        print(f" Positive Tests  : {len(confirmed)}")

        # Technique breakdown
        by_tech = {}
        for f in confirmed:
            tech = f.get("detection_technique", "Unknown")
            by_tech[tech] = by_tech.get(tech, 0) + 1

        if by_tech:
            print(" Breakdown by Technique:")
            for tech, count in by_tech.items():
                print(f"   * {tech:32}: {count} positive")
        print("=" * 70)
