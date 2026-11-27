import time
from typing import List, Dict, Any
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
    1. In-Band / Content-Based SSRF (including alternative notations & redirects)
    2. Limited-Response SSRF
    3. Blind / Out-of-Band (OOB) SSRF
    4. Time-Based SSRF
    5. Boolean-Based SSRF
    Also handles input validation controls and supports both Vulnerable and Secure evaluation modes.
    """

    def __init__(self, client):
        self.client = client
        self.payload_generator = PayloadGenerator()
        self.response_analyzer = ResponseAnalyzer()

        # Initialize modular detection engines
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
        self.raw_probe_results = []
        self.stats = {
            "tests_executed": 0,
            "positive_tests": 0,
            "negative_tests": 0,
            "inconclusive_tests": 0,
            "defense_verified": 0,
            "unique_vulnerabilities": 0
        }

    def _create_error_finding(self, category: str, technique: str, endpoint: str, parameter: str, error: Exception) -> dict:
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
            "test_outcome": "INCONCLUSIVE",
            "extra_metadata": {"error_type": type(error).__name__}
        }

    def _run_negative_controls(self, endpoint: str, parameter: str, mode: str = "vulnerable") -> List[Dict[str, Any]]:
        """Executes Category E negative control probes (unsupported schemes, malformed URLs)."""
        ctrl_probes = self.payload_generator.generate_category_e()
        findings = []
        print(f"\n  [INPUT-VALIDATION] Testing {len(ctrl_probes)} negative control / scheme probes...")

        for probe in ctrl_probes:
            params = {parameter: probe["payload"]}
            if mode == "secure":
                params["mode"] = "secure"

            response = self.client.get(endpoint, params=params)
            metrics = self.response_analyzer.extract_metrics(response)
            status_code = metrics["status_code"]

            # If the application rejected the malformed/unsupported scheme (e.g. 400 or 403), that's expected
            is_blocked = (status_code in (400, 403, 502))
            test_outcome = "DEFENSE_VERIFIED" if is_blocked else "SECURITY_FAILURE"

            finding = self.response_analyzer.create_finding(
                category="INPUT_VALIDATION",
                technique="Scheme & Syntax Validation",
                endpoint=endpoint,
                parameter=parameter,
                payload=probe["payload"],
                response=response,
                detected=not is_blocked,
                confidence="LAB_CONFIRMED" if is_blocked else "HIGH",
                evidence=[f"Scheme/input validation check: status={status_code} (Blocked={is_blocked})."],
                verification_method="Negative Control Invariance Check",
                extra_metadata={
                    "probe_id": probe["id"],
                    "probe_name": probe["name"],
                    "test_outcome": test_outcome,
                    "mode": mode
                }
            )
            findings.append(finding)
        return findings

    def scan(self, parameters: list, mode: str = "vulnerable") -> List[Dict[str, Any]]:
        """
        Executes complete multi-engine SSRF scan against candidate parameters.
        mode can be 'vulnerable' (evaluating flaws) or 'secure' (evaluating defenses).
        """
        print("\n" + "=" * 65)
        print(f"          STARTING MULTI-ENGINE SSRF DETECTION [MODE: {mode.upper()}]")
        print("=" * 65)

        self.findings = []
        self.raw_probe_results = []
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

            # 1. Negative Control / Scheme Validation
            try:
                ctrl_findings = self._run_negative_controls(endpoint, parameter_name, mode=mode)
                self.raw_probe_results.extend(ctrl_findings)
            except Exception as err:
                print(f"  [ERROR] Negative control probe error: {err}")
                self.raw_probe_results.append(self._create_error_finding("INPUT_VALIDATION", "Scheme Validation", endpoint, parameter_name, err))

            # 2. In-Band / Content-Based SSRF (Categories A, B, C, D)
            try:
                inband_findings = self.inband_detector.scan(endpoint, parameter_name, mode=mode)
                self.raw_probe_results.extend(inband_findings)
            except Exception as err:
                print(f"  [ERROR] In-Band detector error: {err}")
                self.raw_probe_results.append(self._create_error_finding("INBAND_SSRF", "In-Band / Content-Based", endpoint, parameter_name, err))

            # 3. Limited-Response SSRF (Category F)
            try:
                limited_findings = self.limited_detector.scan(endpoint, parameter_name, mode=mode)
                self.raw_probe_results.extend(limited_findings)
            except Exception as err:
                print(f"  [ERROR] Limited-Response detector error: {err}")
                self.raw_probe_results.append(self._create_error_finding("LIMITED_RESPONSE_SSRF", "Limited-Response", endpoint, parameter_name, err))

            # 4. Blind / Out-of-Band (OOB) SSRF (Category I)
            try:
                blind_findings = self.blind_detector.scan(endpoint, parameter_name, mode=mode)
                self.raw_probe_results.extend(blind_findings)
            except Exception as err:
                print(f"  [ERROR] Blind / OOB detector error: {err}")
                self.raw_probe_results.append(self._create_error_finding("BLIND_OOB_SSRF", "Blind / Out-of-Band", endpoint, parameter_name, err))

            # 5. Time-Based SSRF (Category G)
            try:
                time_findings = self.time_detector.scan(endpoint, parameter_name, mode=mode)
                self.raw_probe_results.extend(time_findings)
            except Exception as err:
                print(f"  [ERROR] Time-Based detector error: {err}")
                self.raw_probe_results.append(self._create_error_finding("TIME_BASED_SSRF", "Time-Based", endpoint, parameter_name, err))

            # 6. Boolean-Based SSRF (Category H)
            try:
                boolean_findings = self.boolean_detector.scan(endpoint, parameter_name, mode=mode)
                self.raw_probe_results.extend(boolean_findings)
            except Exception as err:
                print(f"  [ERROR] Boolean-Based detector error: {err}")
                self.raw_probe_results.append(self._create_error_finding("BOOLEAN_BASED_SSRF", "Boolean-Based", endpoint, parameter_name, err))

        # Tally metrics
        total = len(self.raw_probe_results)
        positives = sum(1 for f in self.raw_probe_results if f.get("detected") is True)
        defenses = sum(1 for f in self.raw_probe_results if f.get("extra_metadata", {}).get("test_outcome") == "DEFENSE_VERIFIED")
        inconclusives = sum(1 for f in self.raw_probe_results if f.get("confidence") == "INCONCLUSIVE")
        negatives = total - positives - inconclusives

        self.stats = {
            "tests_executed": total,
            "positive_tests": positives,
            "negative_tests": negatives,
            "inconclusive_tests": inconclusives,
            "defense_verified": defenses,
            "unique_vulnerabilities": 0  # Updated during consolidation
        }

        # Consolidate raw probes into findings
        self.findings = self.raw_probe_results
        return self.findings

    def display_results(self):
        print("\n" + "=" * 65)
        print("               SSRF SENTINEL - DETECTION SUMMARY")
        print("=" * 65)

        detected_probes = [f for f in self.findings if f.get("detected") is True]

        if not detected_probes:
            print("\n[+] No SSRF vulnerabilities detected across candidate parameters.")
            defenses = sum(1 for f in self.findings if f.get("extra_metadata", {}).get("test_outcome") == "DEFENSE_VERIFIED")
            if defenses > 0:
                print(f"[INFO] Verified {defenses} defensive controls active in application.")
        else:
            for idx, f in enumerate(detected_probes, 1):
                category = f.get("vulnerability_category", "UNKNOWN")
                technique = f.get("detection_technique", "UNKNOWN")
                endpoint = f.get("endpoint", "")
                param = f.get("parameter", "")
                payload = f.get("payload", "")
                confidence = f.get("confidence", "NONE")
                method = f.get("verification_method", "N/A")
                evidence_list = f.get("evidence", [])

                print(f"\n[{idx}] VULNERABILITY CONFIRMED: {technique}")
                print(f"    Category   : {category}")
                print(f"    Endpoint   : {endpoint}")
                print(f"    Parameter  : {param}")
                print(f"    Payload    : {payload}")
                print(f"    Confidence : {confidence}")
                print(f"    Method     : {method}")
                for ev in evidence_list[:2]:
                    print(f"    - Evidence : {ev}")

        print("\n" + "-" * 65)
        print(f" Total Tests Executed : {self.stats['tests_executed']}")
        print(f" Positive Probe Hits  : {self.stats['positive_tests']}")
        print(f" Negative / Clean     : {self.stats['negative_tests']}")
        print(f" Inconclusive Tests   : {self.stats['inconclusive_tests']}")
        print(f" Defensive Controls   : {self.stats['defense_verified']}")
        print("=" * 65)
