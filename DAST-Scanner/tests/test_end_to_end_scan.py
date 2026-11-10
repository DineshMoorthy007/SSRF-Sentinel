import unittest
import time
import json
import os
from tests.mock_target_server import TargetServerCluster
from core.scanner import Scanner


class TestEndToEndScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cluster = TargetServerCluster()
        cls.cluster.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.cluster.stop()

    def test_full_pipeline_repeatability(self):
        # Scan 1: First Run
        scanner1 = Scanner()
        self.assertTrue(scanner1.check_target(), "Target health check failed on scan 1")
        scanner1.discover_endpoints()
        self.assertTrue(len(scanner1.endpoints) > 0, "No endpoints discovered on scan 1")

        scanner1.analyze_parameters()
        self.assertTrue(len(scanner1.parameters) > 0, "No parameters analyzed on scan 1")

        scanner1.detect_ssrf()
        self.assertTrue(len(scanner1.findings) > 0, "No SSRF findings on scan 1")

        report_path1 = scanner1.generate_reports()
        scanner1.close()

        self.assertTrue(os.path.exists(report_path1))
        with open(report_path1, "r", encoding="utf-8") as f:
            data1 = json.load(f)

        # Validate findings structure and categories in scan 1
        summary1 = data1["scan_summary"]
        self.assertGreater(summary1["positive_findings"], 0)
        self.assertGreater(summary1["negative_tests"], 0)

        det_sum1 = data1["detection_summary"]
        self.assertGreater(det_sum1["inband_findings"], 0, "In-band findings missing")
        self.assertGreater(det_sum1["limited_response_findings"], 0, "Limited response findings missing")
        self.assertGreater(det_sum1["blind_oob_findings"], 0, "Blind OOB findings missing")
        self.assertGreater(det_sum1["time_based_findings"], 0, "Time-based findings missing")
        self.assertGreater(det_sum1["boolean_based_findings"], 0, "Boolean-based findings missing")

        # Scan 2: Repeatability Run
        print("\n[TEST] Running second scan for repeatability evaluation...")
        scanner2 = Scanner()
        self.assertTrue(scanner2.check_target(), "Target health check failed on scan 2")
        scanner2.discover_endpoints()
        scanner2.analyze_parameters()
        scanner2.detect_ssrf()
        report_path2 = scanner2.generate_reports()
        scanner2.close()

        with open(report_path2, "r", encoding="utf-8") as f:
            data2 = json.load(f)

        summary2 = data2["scan_summary"]
        det_sum2 = data2["detection_summary"]

        # Assert repeatability
        self.assertEqual(summary1["positive_findings"], summary2["positive_findings"], "Inconsistent finding count across repeated runs")
        self.assertEqual(det_sum1["inband_findings"], det_sum2["inband_findings"])
        self.assertEqual(det_sum1["limited_response_findings"], det_sum2["limited_response_findings"])
        self.assertEqual(det_sum1["blind_oob_findings"], det_sum2["blind_oob_findings"])
        self.assertEqual(det_sum1["time_based_findings"], det_sum2["time_based_findings"])
        self.assertEqual(det_sum1["boolean_based_findings"], det_sum2["boolean_based_findings"])
        print("\n[SUCCESS] Pipeline repeatability confirmed across back-to-back complete scans.")


if __name__ == "__main__":
    unittest.main()

