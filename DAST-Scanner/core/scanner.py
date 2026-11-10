import time
from core.http_client import HTTPClient
from engine.endpoint_discovery import EndpointDiscovery
from engine.parameter_analyzer import ParameterAnalyzer
from engine.ssrf_detector import SSRFDetector
from reporting.json_reporter import JSONReporter

from config import (
    PROJECT_NAME,
    VERSION,
    TARGET_URL
)


class Scanner:

    def __init__(self):
        self.start_time = time.time()
        self.client = HTTPClient()
        self.discovery = EndpointDiscovery(self.client)
        self.parameter_analyzer = ParameterAnalyzer()
        self.ssrf_detector = SSRFDetector(self.client)
        self.json_reporter = JSONReporter()

        self.endpoints = []
        self.parameters = []
        self.findings = []

    def display_banner(self):
        print("=" * 60)
        print(f"         {PROJECT_NAME} v{VERSION}")
        print("         Advanced Multi-Engine SSRF DAST Scanner")
        print("=" * 60)
        print(f"\n[INFO] Target: {TARGET_URL}")

    def check_target(self):
        print("\n[INFO] Checking target availability...")
        response = self.client.get("/health")

        if response is None:
            print("[ERROR] Target is unreachable.")
            return False

        if response.status_code == 200:
            print("[SUCCESS] Target is reachable.")
            print(f"[INFO] HTTP Status: {response.status_code}")
            return True

        print(f"[WARNING] Target returned HTTP {response.status_code}")
        return False

    def discover_endpoints(self):
        self.endpoints = self.discovery.discover()
        self.discovery.enumerate_paths()
        self.endpoints = list(self.discovery.discovered.values())
        self.discovery.display_results(self.endpoints)

    def analyze_parameters(self):
        self.parameters = self.parameter_analyzer.analyze(self.endpoints)
        self.parameter_analyzer.display_results()

    def detect_ssrf(self):
        self.findings = self.ssrf_detector.scan(self.parameters)
        self.ssrf_detector.display_results()

    def generate_reports(self):
        print("\n[INFO] Generating scan reports...")
        duration = time.time() - self.start_time
        report_path = self.json_reporter.generate_report(
            endpoints=self.endpoints,
            parameters=self.parameters,
            findings=self.findings,
            total_tests=len(self.findings),
            scan_duration_seconds=duration
        )
        print("\n[SUCCESS] Scan reporting completed.")
        return report_path

    def close(self):
        if hasattr(self.ssrf_detector, "blind_detector") and hasattr(self.ssrf_detector.blind_detector, "close"):
            self.ssrf_detector.blind_detector.close()
        self.client.close()
