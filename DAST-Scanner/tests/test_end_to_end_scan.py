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
        self.assertIn("scan_information", data1)
        self.assertIn("scan_summary", data1)
        self.assertIn("vulnerability_findings", data1)

        summary1 = data1["scan_summary"]
        self.assertGreater(summary1["positive_results"], 0)
        self.assertGreater(summary1["negative_results"], 0)

        findings1 = data1["vulnerability_findings"]
        techniques1 = {f["detection_technique"] for f in findings1}
        self.assertIn("In-Band / Content-Based", techniques1, "In-band findings missing")
        self.assertIn("Limited-Response", techniques1, "Limited response findings missing")
        self.assertIn("Blind / Out-of-Band", techniques1, "Blind OOB findings missing")
        self.assertIn("Time-Based", techniques1, "Time-based findings missing")
        self.assertIn("Boolean-Based", techniques1, "Boolean-based findings missing")

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
        findings2 = data2["vulnerability_findings"]

        # Assert repeatability
        self.assertEqual(summary1["positive_results"], summary2["positive_results"], "Inconsistent finding count across repeated runs")
        self.assertEqual(len(findings1), len(findings2), "Inconsistent findings length")
        print("\n[SUCCESS] Pipeline repeatability confirmed across back-to-back complete scans.")


if __name__ == "__main__":
    unittest.main()

