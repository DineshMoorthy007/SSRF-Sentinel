import time
import os
import sys
from typing import List, Dict, Any
from core.http_client import HTTPClient
from engine.endpoint_discovery import EndpointDiscovery
from engine.parameter_analyzer import ParameterAnalyzer
from engine.ssrf_detector import SSRFDetector
from reporting.json_reporter import JSONReporter
from reporting.html_reporter import HTMLReporter

from config import (
    PROJECT_NAME,
    VERSION,
    TARGET_URL
)


class ReportPaths(str):
    """
    Backwards-compatible report path container.
    Acts as a str (pointing to the primary JSON report) for legacy integrations,
    while providing dictionary access (paths['json'], paths['html']) and attributes
    (paths.json, paths.html) for unified multi-format reporting.
    """
    def __new__(cls, json_path: str, html_path: str):
        obj = super().__new__(cls, json_path)
        obj.json = json_path
        obj.html = html_path
        return obj

    def __getitem__(self, item):
        if item == "json":
            return self.json
        elif item == "html":
            return self.html
        return super().__getitem__(item)

    def get(self, item, default=None):
        if item == "json":
            return self.json
        elif item == "html":
            return self.html
        return default


class Scanner:
    """
    Main DAST Scanner orchestrator for SSRF Sentinel.
    Integrates directly and exclusively with the actual C++ SSRF Target Application.
    Generates unified JSON and HTML vulnerability reports.
    """

    def __init__(self, mode: str = "vulnerable"):
        self.mode = mode.lower()
        self.start_time = time.time()
        self.client = HTTPClient()
        self.discovery = EndpointDiscovery(self.client)
        self.parameter_analyzer = ParameterAnalyzer()
        self.ssrf_detector = SSRFDetector(self.client)
        self.json_reporter = JSONReporter()
        self.html_reporter = HTMLReporter()

        self.endpoints = []
        self.parameters = []
        self.findings = []

    def display_banner(self):
        print("=" * 65)
        print(f"         {PROJECT_NAME} v{VERSION}")
        print("         Advanced Multi-Engine SSRF DAST Scanner")
        print("=" * 65)
        print(f"\n[INFO] Target Environment : {TARGET_URL}")
        print(f"[INFO] Evaluation Mode    : {self.mode.upper()}")
        print(f"[INFO] Target Integration : C++ Native Server (Mandatory)")

    def check_target(self) -> bool:
        """
        Validates target reachability on port 8080.
        MANDATORY REQUIREMENT: If the actual C++ application is unreachable,
        the scanner aborts immediately without mock fallback.
        """
        print("\n[INFO] Checking C++ target application availability (127.0.0.1:8080)...")
        response = self.client.get("/health")

        if response is None or response.status_code != 200:
            print("\n" + "!" * 65)
            print("[FATAL ERROR] The C++ SSRF Target Application is NOT reachable.")
            print("Integration testing cannot proceed without the actual C++ target.")
            print("=" * 65)
            print("Please start the C++ target executable first:")
            print("  cd SSRF-Target/build")
            print("  ssrf_target.exe")
            print("=" * 65)
            print("Do NOT substitute a mock target for actual integration scans.")
            print("!" * 65)
            return False

        print("[SUCCESS] C++ target application is active and reachable.")
        print(f"[INFO] HTTP Status: {response.status_code} | Service: {response.headers.get('Content-Type', 'application/json')}")
        return True

    def discover_endpoints(self):
        self.endpoints = self.discovery.discover()
        self.discovery.enumerate_paths()
        self.endpoints = list(self.discovery.discovered.values())
        self.discovery.display_results(self.endpoints)

    def analyze_parameters(self):
        self.parameters = self.parameter_analyzer.analyze(self.endpoints)
        self.parameter_analyzer.display_results()

    def detect_ssrf(self):
        self.findings = self.ssrf_detector.scan(self.parameters, mode=self.mode)
        self.ssrf_detector.display_results()

    def generate_reports(self, filename: str = "ssrf_report.json") -> Dict[str, str]:
        print("\n[INFO] Generating scan reports (JSON & HTML)...")
        duration = time.time() - self.start_time

        # 1. Primary JSON report
        json_path = self.json_reporter.generate_report(
            endpoints=self.endpoints,
            parameters=self.parameters,
            findings=self.findings,
            total_tests=len(self.findings),
            scan_duration_seconds=duration,
            output_filename=filename,
            scan_mode=self.mode
        )

        # 2. Synchronized HTML report from the exact same scan data
        html_filename = os.path.splitext(filename)[0] + ".html"
        html_path = self.html_reporter.generate_report(
            report_data=self.json_reporter.last_report_data,
            output_filename=html_filename,
            raw_probes=self.findings
        )

        print(f"\n[SUCCESS] Reporting completed:")
        print(f"  - JSON Report : {json_path}")
        print(f"  - HTML Report : {html_path}")

        return ReportPaths(json_path=json_path, html_path=html_path)

    def close(self):
        if hasattr(self.ssrf_detector, "blind_detector") and hasattr(self.ssrf_detector.blind_detector, "close"):
            self.ssrf_detector.blind_detector.close()
        self.client.close()
