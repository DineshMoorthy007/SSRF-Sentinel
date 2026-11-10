import json
from config import (
    VERIFICATION_MARKER,
    INBAND_MARKER,
    LIMITED_HEADER_MARKER,
    BOOLEAN_TRUE_MARKER,
    TIME_FAST_MARKER,
    TIME_DELAYED_MARKER
)


class ResponseAnalyzer:
    """
    Standardized HTTP response analyzer for SSRF detection.
    Extracts protocol metrics, validates fingerprints, and calculates confidence ratings.
    """

    KNOWN_MARKERS = [
        VERIFICATION_MARKER,
        INBAND_MARKER,
        LIMITED_HEADER_MARKER,
        BOOLEAN_TRUE_MARKER,
        TIME_FAST_MARKER,
        TIME_DELAYED_MARKER
    ]

    INTERNAL_FINGERPRINTS = [
        "Internal Test Service",
        "Internal Admin Core",
        "SSRF-Sentinel-Core",
        "SSRF-Sentinel-Mock",
        "admin-config-vault",
        "database_uri",
        "admin_session_key",
        "postgresql://",
        "127.0.0.1/32"
    ]

    @staticmethod
    def extract_metrics(response):
        """Extracts status code, headers, length, body, and latency from a requests.Response."""
        if response is None:
            return {
                "status_code": None,
                "headers": {},
                "body": "",
                "length": 0,
                "latency_ms": None,
                "content_type": ""
            }

        latency_ms = None
        if hasattr(response, "elapsed") and response.elapsed is not None:
            latency_ms = round(response.elapsed.total_seconds() * 1000, 2)

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.text or "",
            "length": len(response.content or b""),
            "latency_ms": latency_ms,
            "content_type": response.headers.get("Content-Type", "")
        }

    def inspect_inband(self, metrics, expected_marker=None):
        """Inspects response for full-content disclosures and internal signatures."""
        evidence = []
        body = metrics["body"]
        headers = metrics["headers"]

        # Check for exact verification markers
        found_markers = [m for m in self.KNOWN_MARKERS if m in body]
        if expected_marker and expected_marker in body and expected_marker not in found_markers:
            found_markers.append(expected_marker)

        # Check for header markers
        for h_name, h_val in headers.items():
            if h_name.startswith("X-Internal") or h_name.startswith("X-Resource"):
                evidence.append(f"Disclosed internal header: {h_name}={h_val}")

        # Check for known internal signatures
        found_signatures = [s for s in self.INTERNAL_FINGERPRINTS if s in body]

        if found_markers:
            evidence.append(f"Confirmed internal verification marker: {', '.join(found_markers)}")
            return {
                "detected": True,
                "confidence": "LAB_CONFIRMED",
                "evidence": evidence,
                "verification_method": "Exact Cryptographic/Verification Marker Matching"
            }

        if found_signatures:
            evidence.append(f"Disclosed internal infrastructure signatures: {', '.join(found_signatures)}")
            return {
                "detected": True,
                "confidence": "HIGH",
                "evidence": evidence,
                "verification_method": "Internal Service Architecture Heuristics"
            }

        # Check if JSON contains sensitive internal fields
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                # Discard public health responses
                if parsed.get("service") == "Public Application":
                    pass
                elif any(k in parsed for k in ("database_uri", "admin_session_key", "internal_network", "verification_marker")):
                    evidence.append(f"Disclosed sensitive internal JSON fields: {[k for k in parsed if k in ('database_uri', 'admin_session_key', 'internal_network', 'verification_marker')]}")
                    return {
                        "detected": True,
                        "confidence": "HIGH",
                        "evidence": evidence,
                        "verification_method": "Internal Credential & Config Disclosure"
                    }
                elif "classification" in parsed and parsed.get("classification") == "Restricted":
                    evidence.append("Internal classified resource descriptor discovered in JSON.")
                    return {
                        "detected": True,
                        "confidence": "HIGH",
                        "evidence": evidence,
                        "verification_method": "Restricted Internal Resource Classification"
                    }
        except Exception:
            pass

        return {
            "detected": False,
            "confidence": "NONE",
            "evidence": ["No identifiable internal data or markers discovered"],
            "verification_method": "Negative Marker Scan"
        }

    def create_finding(
        self,
        category,
        technique,
        endpoint,
        parameter,
        payload,
        response,
        detected,
        confidence,
        evidence,
        verification_method,
        extra_metadata=None
    ):
        """Constructs a normalized finding dictionary conforming to reporting requirements."""
        metrics = self.extract_metrics(response)

        finding = {
            "vulnerability_category": category,
            "detection_technique": technique,
            "endpoint": endpoint,
            "parameter": parameter,
            "payload": payload,
            "http_status": metrics["status_code"],
            "response_time_ms": metrics["latency_ms"],
            "response_length": metrics["length"],
            "detected": detected,
            "confidence": confidence,
            "evidence": evidence if isinstance(evidence, list) else [str(evidence)],
            "verification_method": verification_method,
            "test_outcome": "POSITIVE" if detected else "NEGATIVE",
            "raw_evidence": {
                "status": metrics["status_code"],
                "content_type": metrics["content_type"],
                "headers": {k: v for k, v in metrics["headers"].items() if k.startswith("X-") or k == "Content-Type"},
                "body_snippet": metrics["body"][:200] if metrics["body"] else ""
            }
        }

        if extra_metadata and isinstance(extra_metadata, dict):
            finding["extra_metadata"] = extra_metadata
            finding["raw_evidence"].update(extra_metadata)
        else:
            finding["extra_metadata"] = {}

        return finding

    def analyze(self, payload_info, response):
        """Legacy analyze method preserved for backward compatibility."""
        metrics = self.extract_metrics(response)
        body = metrics["body"]

        result = {
            "payload_name": payload_info.get("name", "Unknown"),
            "payload": payload_info.get("payload", ""),
            "category": payload_info.get("category", "UNKNOWN"),
            "http_status": metrics["status_code"],
            "detected": False,
            "confidence": "NONE",
            "evidence": []
        }

        if response is None:
            result["evidence"].append("No HTTP response received")
            return result

        inband_eval = self.inspect_inband(metrics, payload_info.get("expected"))
        if inband_eval["detected"]:
            result["detected"] = True
            result["confidence"] = inband_eval["confidence"]
            result["evidence"] = inband_eval["evidence"]
        elif payload_info.get("category") == "CONTROL_TEST":
            result["evidence"].append("Control destination did not leak internal data")
        else:
            result["evidence"].append("Expected internal resource evidence was not found")

        return result
