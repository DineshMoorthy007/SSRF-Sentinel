import unittest
import time
from core.http_client import HTTPClient
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer
from engine.inband_detector import InBandDetector
from engine.limited_response_detector import LimitedResponseDetector
from engine.blind_oob_detector import BlindOOBDetector
from engine.time_based_detector import TimeBasedDetector
from engine.boolean_based_detector import BooleanBasedDetector


class TestGroundTruthValidation(unittest.TestCase):
    """
    Ground-Truth Validation Suite for SSRF Sentinel.
    Evaluates all 10 documented test scenarios against the actual C++ SSRF Target Application:
    1. In-Band SSRF
    2. Limited-Response SSRF
    3. Blind / OOB SSRF
    4. Time-Based SSRF
    5. Boolean-Based SSRF
    6. Redirect handling
    7. URL validation & alternative IP notations
    8. Secure-mode restrictions
    9. Ordinary health endpoint (Negative control)
    10. Invalid URL / scheme rejection (Negative control)
    """

    @classmethod
    def setUpClass(cls):
        cls.client = HTTPClient()
        resp = cls.client.get("/health")
        if resp is None or resp.status_code != 200:
            raise RuntimeError(
                "Actual C++ target application is NOT running on 127.0.0.1:8080! "
                "Start 'ssrf_target.exe' before running ground-truth tests."
            )
        cls.payload_generator = PayloadGenerator()
        cls.response_analyzer = ResponseAnalyzer()
        cls.inband = InBandDetector(cls.client, cls.response_analyzer, cls.payload_generator)
        cls.limited = LimitedResponseDetector(cls.client, cls.response_analyzer, cls.payload_generator)
        cls.blind = BlindOOBDetector(cls.client, cls.response_analyzer, cls.payload_generator)
        cls.time_detector = TimeBasedDetector(cls.client, cls.response_analyzer, cls.payload_generator)
        cls.boolean = BooleanBasedDetector(cls.client, cls.response_analyzer, cls.payload_generator)

    @classmethod
    def tearDownClass(cls):
        cls.blind.close()
        cls.client.close()

    def test_01_inband_ssrf_detection(self):
        """GT-01: In-Band SSRF detects internal secret and admin credentials."""
        findings = self.inband.scan("/fetch", "url", mode="vulnerable")
        detected = [f for f in findings if f.get("detected") is True]
        self.assertGreaterEqual(len(detected), 3, "Expected at least 3 positive In-Band disclosures")
        self.assertTrue(any(f["confidence"] == "LAB_CONFIRMED" for f in detected))

    def test_02_limited_response_ssrf(self):
        """GT-02: Limited-response detector verifies 204 status, headers, truncated and suppressed data."""
        findings = self.limited.scan("/fetch", "url", mode="vulnerable")
        detected = [f for f in findings if f.get("detected") is True]
        self.assertGreaterEqual(len(detected), 4, "Expected at least 4 limited-response positives")

    def test_03_blind_oob_ssrf(self):
        """GT-03: Blind OOB SSRF verifies callback arrival on dedicated receiver (port 8090)."""
        findings = self.blind.scan("/fetch", "url", mode="vulnerable")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["detected"], "Expected Blind OOB callback to be received")
        self.assertEqual(findings[0]["confidence"], "LAB_CONFIRMED")

    def test_04_time_based_ssrf(self):
        """GT-04: Time-based detector calculates statistically significant latency delta."""
        findings = self.time_detector.scan("/fetch", "url", mode="vulnerable")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["detected"], "Expected Time-Based SSRF to be detected")
        self.assertEqual(findings[0]["confidence"], "HIGH")

    def test_05_boolean_based_ssrf(self):
        """GT-05: Boolean-based detector identifies status and length differential (200 vs 404)."""
        findings = self.boolean.scan("/fetch", "url", mode="vulnerable")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["detected"], "Expected Boolean-Based SSRF to be detected")
        self.assertEqual(findings[0]["confidence"], "LAB_CONFIRMED")

    def test_06_redirect_ssrf_handling(self):
        """GT-06: Verifies redirect following reaches internal protected secret."""
        probe = self.payload_generator.generate_category_d()[0]  # PL-REDIR-INT-001
        resp = self.client.get("/fetch", params={"url": probe["payload"]})
        metrics = self.response_analyzer.extract_metrics(resp)
        eval_res = self.response_analyzer.inspect_inband(metrics, "SSRF_SENTINEL_INTERNAL_ACCESS_2026")
        self.assertTrue(eval_res["detected"], "Redirect SSRF should reach internal secret in vulnerable mode")

    def test_07_alternative_ip_representations(self):
        """GT-07: Verifies alternative notations (decimal, shorthand, octal, hex, IPv6) reach target."""
        bypasses = self.payload_generator.generate_category_b()
        for probe in bypasses:
            resp = self.client.get("/fetch", params={"url": probe["payload"]})
            self.assertEqual(resp.status_code, 200, f"Expected 200 for {probe['name']}")
            self.assertIn("SSRF_SENTINEL_INTERNAL_ACCESS_2026", resp.text)

    def test_08_secure_mode_restrictions(self):
        """GT-08: Verifies that in secure mode, internal service and bypasses are blocked (HTTP 403)."""
        # 1. Direct internal request blocked
        resp1 = self.client.get("/fetch", params={"url": "http://127.0.0.1:8081/internal/secret", "mode": "secure"})
        self.assertEqual(resp1.status_code, 403)
        self.assertIn("ERR_INTERNAL_PORT_BLOCKED", resp1.text)

        # 2. Alternative IP notation blocked
        resp2 = self.client.get("/fetch", params={"url": "http://2130706433:8081/internal/secret", "mode": "secure"})
        self.assertEqual(resp2.status_code, 403)
        self.assertIn("ERR_NON_CANONICAL_HOST", resp2.text)

        # 3. Dedicated /fetch-secure endpoint blocks
        resp3 = self.client.get("/fetch-secure", params={"url": "http://127.0.0.1:8081/internal/secret"})
        self.assertEqual(resp3.status_code, 403)

    def test_09_ordinary_health_endpoint_control(self):
        """GT-09: Negative Control: Non-SSRF public endpoint does not leak internal resources."""
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("SSRF_SENTINEL_INTERNAL_ACCESS_2026", resp.text)
        self.assertNotIn("SSRF_SENTINEL_INBAND_FULL_ACCESS", resp.text)

    def test_10_invalid_scheme_rejection_control(self):
        """GT-10: Negative Control: Unsupported schemes (file://, gopher://, ftp://) rejected with HTTP 400."""
        schemes = ["file:///etc/passwd", "gopher://127.0.0.1:8081/_", "ftp://127.0.0.1:8081/"]
        for s in schemes:
            resp = self.client.get("/fetch", params={"url": s})
            self.assertEqual(resp.status_code, 400, f"Scheme {s} should be rejected with HTTP 400")


if __name__ == "__main__":
    unittest.main()
