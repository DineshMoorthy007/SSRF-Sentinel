import uuid
from config import (
    TARGET_URL,
    INTERNAL_SERVICE_URL,
    CALLBACK_RECEIVER_URL,
    INTERNAL_TEST_PATH,
    INTERNAL_STATUS_PATH,
    VERIFICATION_MARKER,
    INBAND_MARKER,
    LIMITED_HEADER_MARKER,
    TIME_FAST_MARKER,
    TIME_DELAYED_MARKER,
    BOOLEAN_TRUE_MARKER,
    TIME_DELAY_SECONDS
)


class PayloadGenerator:
    """
    Generates structured test payloads for multiple SSRF vulnerability behaviors.
    All default probes are strictly constrained to the controlled local test environment.
    """

    def __init__(self):
        self.internal_url = INTERNAL_SERVICE_URL.rstrip("/")
        self.callback_url = CALLBACK_RECEIVER_URL.rstrip("/")
        self.public_url = TARGET_URL.rstrip("/")

    def generate_inband_payloads(self):
        """Generates payloads targeting full-content internal disclosures."""
        return [
            {
                "id": "INBAND_SECRET_PROBE",
                "name": "Internal Secret Access",
                "category": "INBAND",
                "technique": "In-Band / Content-Based",
                "payload": f"{self.internal_url}{INTERNAL_TEST_PATH}",
                "expected": {
                    "marker": VERIFICATION_MARKER,
                    "fields": ["verification_marker", "resource"]
                },
                "description": "Baseline internal secret containing authorization marker."
            },
            {
                "id": "INBAND_ADMIN_CONFIG",
                "name": "Internal Admin Core Config",
                "category": "INBAND",
                "technique": "In-Band / Content-Based",
                "payload": f"{self.internal_url}/internal/admin/config",
                "expected": {
                    "marker": INBAND_MARKER,
                    "fields": ["admin_session_key", "database_uri"]
                },
                "description": "Administrative credentials and database connection string."
            },
            {
                "id": "INBAND_STATUS_PROBE",
                "name": "Internal Status Service",
                "category": "INBAND",
                "technique": "In-Band / Content-Based",
                "payload": f"{self.internal_url}{INTERNAL_STATUS_PATH}",
                "expected": {
                    "marker": "Internal Test Service",
                    "fields": ["service", "environment"]
                },
                "description": "Service heartbeat exposing internal network environment."
            }
        ]

    def generate_limited_payloads(self):
        """Generates payloads testing restricted response scenarios."""
        return [
            {
                "id": "LIMITED_STATUS_ONLY",
                "name": "Status-Only Response (204 No Content)",
                "category": "LIMITED_RESPONSE",
                "technique": "Limited-Response SSRF",
                "payload": f"{self.internal_url}/internal/limited/status-only",
                "expected": {
                    "status_code": 204,
                    "body_empty": True
                },
                "description": "Probe expecting HTTP 204 status with suppressed body."
            },
            {
                "id": "LIMITED_HEADER_ONLY",
                "name": "Header-Only Information Leak",
                "category": "LIMITED_RESPONSE",
                "technique": "Limited-Response SSRF",
                "payload": f"{self.internal_url}/internal/limited/header-only",
                "expected": {
                    "header_marker": LIMITED_HEADER_MARKER,
                    "expected_header": "X-Internal-Marker"
                },
                "description": "Probe evaluating headers while response body is suppressed."
            },
            {
                "id": "LIMITED_TRUNCATED",
                "name": "Truncated Internal Response",
                "category": "LIMITED_RESPONSE",
                "technique": "Limited-Response SSRF",
                "payload": f"{self.internal_url}/internal/limited/truncated",
                "expected": {
                    "prefix": "SSRF_SECRET_SEGMENT_PARTIAL_DATA",
                    "is_truncated": True
                },
                "description": "Probe returning partial or truncated memory/string buffers."
            },
            {
                "id": "LIMITED_GENERIC",
                "name": "Generic Success Message",
                "category": "LIMITED_RESPONSE",
                "technique": "Limited-Response SSRF",
                "payload": f"{self.internal_url}/internal/limited/generic",
                "expected": {
                    "message": "Internal request processed successfully"
                },
                "description": "Generic acknowledgement confirming internal execution."
            },
            {
                "id": "LIMITED_SUPPRESSED",
                "name": "Content-Filter Suppressed Body",
                "category": "LIMITED_RESPONSE",
                "technique": "Limited-Response SSRF",
                "payload": f"{self.internal_url}/internal/limited/suppressed",
                "expected": {
                    "suppression_token": "[CONTENT_SUPPRESSED_BY_POLICY]"
                },
                "description": "Sanitized response indicating policy filtering of internal data."
            }
        ]

    def generate_oob_payload(self, token: str = None):
        """Generates a dedicated Out-of-Band callback probe with a unique tracking token."""
        if not token:
            token = f"tok_{uuid.uuid4().hex[:12]}"
        return {
            "id": "BLIND_OOB_CALLBACK",
            "name": "Dedicated OOB Callback Probe",
            "category": "BLIND_OOB",
            "technique": "Blind / Out-of-Band SSRF",
            "token": token,
            "payload": f"{self.callback_url}/callback?token={token}",
            "expected": {
                "callback_received": True,
                "token_match": token
            },
            "description": "Server-side request forced to dedicated local callback receiver."
        }

    def generate_time_based_payloads(self):
        """Generates paired fast baseline and delayed timing probes."""
        ms_delay = int(TIME_DELAY_SECONDS * 1000)
        return {
            "fast": {
                "id": "TIME_FAST_PROBE",
                "name": "Immediate Execution Baseline (<1ms)",
                "category": "TIME_BASED",
                "technique": "Time-Based SSRF",
                "payload": f"{self.internal_url}/internal/fast",
                "expected": {
                    "marker": TIME_FAST_MARKER,
                    "target_delay_sec": 0.0
                },
                "description": "Baseline immediate response for round-trip latency calibration."
            },
            "delayed": {
                "id": "TIME_DELAYED_PROBE",
                "name": f"Bounded Delayed Execution ({TIME_DELAY_SECONDS}s)",
                "category": "TIME_BASED",
                "technique": "Time-Based SSRF",
                "payload": f"{self.internal_url}/internal/delayed?ms={ms_delay}",
                "expected": {
                    "marker": TIME_DELAYED_MARKER,
                    "target_delay_sec": TIME_DELAY_SECONDS
                },
                "description": f"Internal execution sleep introducing a bounded ~{TIME_DELAY_SECONDS}s delay."
            }
        }

    def generate_boolean_payloads(self):
        """Generates differential true and false Boolean evaluation probes."""
        return {
            "true_probe": {
                "id": "BOOLEAN_TRUE_PROBE",
                "name": "Boolean Condition TRUE",
                "category": "BOOLEAN_BASED",
                "technique": "Boolean-Based SSRF",
                "condition": "true",
                "payload": f"{self.internal_url}/internal/check?condition=true",
                "expected": {
                    "status_code": 200,
                    "header_val": "TRUE",
                    "marker": BOOLEAN_TRUE_MARKER
                },
                "description": "Simulates positive condition evaluation (200 OK + padded payload)."
            },
            "false_probe": {
                "id": "BOOLEAN_FALSE_PROBE",
                "name": "Boolean Condition FALSE",
                "category": "BOOLEAN_BASED",
                "technique": "Boolean-Based SSRF",
                "condition": "false",
                "payload": f"{self.internal_url}/internal/check?condition=false",
                "expected": {
                    "status_code": 404,
                    "header_val": "FALSE"
                },
                "description": "Simulates negative condition evaluation (404 Not Found + minimal payload)."
            }
        }

    def generate_control_payloads(self):
        """Generates negative control probes to calibrate target behavior."""
        return [
            {
                "id": "CONTROL_PUBLIC_HEALTH",
                "name": "Public Server Control Test",
                "category": "CONTROL_TEST",
                "technique": "Negative Control",
                "payload": f"{self.public_url}/health",
                "expected": None,
                "description": "Verification that self-targeting loopback doesn't yield internal privilege."
            }
        ]

    def generate(self):
        """Legacy generator method preserved for backward compatibility."""
        payloads = []
        for p in self.generate_inband_payloads():
            payloads.append({
                "name": p["name"],
                "payload": p["payload"],
                "category": "LOCALHOST_SSRF",
                "expected": p["expected"].get("marker")
            })
        for p in self.generate_control_payloads():
            payloads.append({
                "name": p["name"],
                "payload": p["payload"],
                "category": "CONTROL_TEST",
                "expected": None
            })
        return payloads
