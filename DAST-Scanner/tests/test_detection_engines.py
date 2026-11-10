import unittest
from unittest.mock import MagicMock, patch
import requests

from engine.response_analyzer import ResponseAnalyzer
from engine.payload_generator import PayloadGenerator
from engine.inband_detector import InBandDetector
from engine.limited_response_detector import LimitedResponseDetector
from engine.blind_oob_detector import BlindOOBDetector
from engine.time_based_detector import TimeBasedDetector
from engine.boolean_based_detector import BooleanBasedDetector
from engine.ssrf_detector import SSRFDetector


class MockResponse:
    def __init__(self, status_code=200, text="", headers=None, elapsed_seconds=0.01):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")
        self.headers = headers or {"Content-Type": "application/json"}
        self.elapsed = MagicMock()
        self.elapsed.total_seconds.return_value = elapsed_seconds


class TestSSRFDetectionEngines(unittest.TestCase):

    def setUp(self):
        self.analyzer = ResponseAnalyzer()
        self.generator = PayloadGenerator()
        self.mock_client = MagicMock()

    def test_inband_detection_confirmed(self):
        detector = InBandDetector(self.mock_client, self.analyzer, self.generator)
        # Mock response containing the exact verification marker
        self.mock_client.get.return_value = MockResponse(
            status_code=200,
            text='{"resource":"secret","verification_marker":"SSRF_SENTINEL_INTERNAL_ACCESS_2026"}'
        )
        findings = detector.scan(endpoint="/fetch", parameter="url")
        self.assertTrue(len(findings) > 0)
        confirmed = [f for f in findings if f["detected"] and f["confidence"] == "LAB_CONFIRMED"]
        self.assertTrue(len(confirmed) >= 1)

    def test_limited_response_detection(self):
        detector = LimitedResponseDetector(self.mock_client, self.analyzer, self.generator)
        # Mock responses for baseline and test probes
        def side_effect(endpoint, params):
            url = params.get("url", "")
            if "status-only" in url:
                return MockResponse(status_code=204, text="")
            elif "header-only" in url:
                return MockResponse(status_code=200, text="", headers={"X-Internal-Marker": "SSRF_HEADER_ONLY_FLAG"})
            elif "truncated" in url:
                return MockResponse(status_code=200, text='{"status":"success","leak":"SSRF_SECRET_SEGMENT_PARTIAL_DATA')
            elif "generic" in url:
                return MockResponse(status_code=200, text='{"status":"success","message":"Internal request processed successfully"}')
            elif "suppressed" in url:
                return MockResponse(status_code=200, text='{"status":"acknowledged","data":"[CONTENT_SUPPRESSED_BY_POLICY]"}')
            return MockResponse(status_code=403, text="Forbidden")

        self.mock_client.get.side_effect = side_effect
        findings = detector.scan(endpoint="/fetch", parameter="url")
        detected = [f for f in findings if f["detected"]]
        self.assertEqual(len(detected), 5)

    def test_blind_oob_detection(self):
        detector = BlindOOBDetector(self.mock_client, self.analyzer, self.generator)
        detector._generate_test_token = MagicMock(return_value="test_token_12345")
        detector._poll_evidence = MagicMock(return_value={
            "received": True,
            "count": 1,
            "details": [{"source_ip": "127.0.0.1", "timestamp": "2026-11-09T22:00:00Z"}],
            "poll_duration_s": 0.5
        })
        self.mock_client.get.return_value = MockResponse(status_code=200, text='{"status":"received"}')

        findings = detector.scan(endpoint="/fetch", parameter="url")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["detected"])
        self.assertEqual(findings[0]["confidence"], "LAB_CONFIRMED")
        self.assertIn("test_token_12345", findings[0]["extra_metadata"]["oob_token"])

    def test_time_based_detection_never_lab_confirmed(self):
        detector = TimeBasedDetector(self.mock_client, self.analyzer, self.generator)
        detector.iterations = 1
        detector.threshold = 0.5

        def side_effect(endpoint, parameter, target_url):
            if "delayed" in target_url:
                return 2.05, MockResponse(status_code=200, text='{"status":"delayed"}', elapsed_seconds=2.05)
            return 0.02, MockResponse(status_code=200, text='{"status":"fast"}', elapsed_seconds=0.02)

        detector._measure_latency = MagicMock(side_effect=side_effect)
        findings = detector.scan(endpoint="/fetch", parameter="url")

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["detected"])
        # Rule check: A timing anomaly alone must never receive LAB_CONFIRMED!
        self.assertNotEqual(findings[0]["confidence"], "LAB_CONFIRMED")
        self.assertEqual(findings[0]["confidence"], "HIGH")

    def test_boolean_based_detection(self):
        detector = BooleanBasedDetector(self.mock_client, self.analyzer, self.generator)
        detector.iterations = 1

        def side_effect(endpoint, params):
            url = params.get("url", "")
            if "condition=true" in url:
                return MockResponse(
                    status_code=200,
                    text='{"condition":true,"evaluation":"MATCH_TRUE","verification_marker":"SSRF_BOOLEAN_TRUE_VERIFIED","pad":"XXXXX"}',
                    headers={"X-SSRF-Evaluation": "TRUE"}
                )
            return MockResponse(
                status_code=404,
                text='{"condition":false}',
                headers={"X-SSRF-Evaluation": "FALSE"}
            )

        self.mock_client.get.side_effect = side_effect
        findings = detector.scan(endpoint="/fetch", parameter="url")

        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["detected"])
        self.assertEqual(findings[0]["confidence"], "LAB_CONFIRMED")
        self.assertEqual(findings[0]["extra_metadata"]["true_status"], 200)
        self.assertEqual(findings[0]["extra_metadata"]["false_status"], 404)

    def test_ssrf_detector_coordinator(self):
        coordinator = SSRFDetector(self.mock_client)
        # Mock sub-detector outputs
        coordinator.inband_detector.scan = MagicMock(return_value=[{"endpoint": "/fetch", "parameter": "url", "detection_technique": "In-Band", "payload": "p1", "detected": True}])
        coordinator.limited_detector.scan = MagicMock(return_value=[{"endpoint": "/fetch", "parameter": "url", "detection_technique": "Limited", "payload": "p2", "detected": True}])
        coordinator.blind_detector.scan = MagicMock(return_value=[{"endpoint": "/fetch", "parameter": "url", "detection_technique": "Blind", "payload": "p3", "detected": True}])
        coordinator.time_detector.scan = MagicMock(return_value=[{"endpoint": "/fetch", "parameter": "url", "detection_technique": "Time", "payload": "p4", "detected": True}])
        coordinator.boolean_detector.scan = MagicMock(return_value=[{"endpoint": "/fetch", "parameter": "url", "detection_technique": "Boolean", "payload": "p5", "detected": True}])
        coordinator._run_negative_controls = MagicMock(return_value=[{"endpoint": "/fetch", "parameter": "url", "detection_technique": "Control", "payload": "p6", "detected": False}])

        params = [{"endpoint": "/fetch", "parameter": "url", "method": "GET", "ssrf_candidate": True}]
        results = coordinator.scan(params)
        self.assertEqual(len(results), 6)

    def test_json_reporter_compatibility(self):
        from reporting.json_reporter import JSONReporter
        import os
        reporter = JSONReporter()
        endpoints = [{"path": "/fetch", "method": "GET"}]
        parameters = [{"endpoint": "/fetch", "parameter": "url"}]
        findings = [
            {
                "vulnerability_category": "INBAND_SSRF",
                "detection_technique": "In-Band / Content-Based",
                "endpoint": "/fetch",
                "parameter": "url",
                "payload": "http://127.0.0.1:8081/internal/secret",
                "http_status": 200,
                "response_time_ms": 12.5,
                "response_length": 150,
                "detected": True,
                "confidence": "LAB_CONFIRMED",
                "evidence": ["Marker detected"],
                "verification_method": "Marker Check",
                "test_outcome": "POSITIVE",
                "raw_evidence": {}
            }
        ]
        report_file = reporter.generate_report(endpoints, parameters, findings)
        self.assertTrue(os.path.exists(report_file))


if __name__ == "__main__":
    unittest.main()
