import time
import uuid
import requests
from typing import List, Dict, Any
from config import (
    CALLBACK_RECEIVER_URL,
    CALLBACK_POLL_TIMEOUT,
    CALLBACK_POLL_INTERVAL,
    CALLBACK_MAX_RETRIES,
    SCAN_DELAY
)
from engine.payload_generator import PayloadGenerator
from engine.response_analyzer import ResponseAnalyzer


class BlindOOBDetector:
    """
    Detection engine for Blind / Out-of-Band (OOB) SSRF.
    Integrates with the dedicated local callback receiver (port 8090).
    Uses unique high-entropy tokens and bounded polling to verify out-of-band execution.
    A callback must actually be received and verified in the evidence store before reporting detection.
    """

    def __init__(self, client, response_analyzer=None, payload_generator=None, callback_url=None):
        self.client = client
        self.response_analyzer = response_analyzer or ResponseAnalyzer()
        self.payload_generator = payload_generator or PayloadGenerator()
        self.callback_receiver_url = (callback_url or CALLBACK_RECEIVER_URL).rstrip("/")
        self.session = requests.Session()

    def _generate_test_token(self) -> str:
        """Requests a unique token from the callback server or generates a local high-entropy token."""
        try:
            resp = self.session.get(f"{self.callback_receiver_url}/token/generate", timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                if "token" in data:
                    return data["token"]
        except Exception:
            pass
        return f"ssrf_tok_{uuid.uuid4().hex[:16]}"

    def _poll_evidence(self, token: str) -> dict:
        """Polls the callback receiver on port 8090 for evidence correlating to the test token."""
        start_time = time.time()
        attempts = 0

        while (time.time() - start_time) < CALLBACK_POLL_TIMEOUT and attempts < CALLBACK_MAX_RETRIES:
            attempts += 1
            try:
                evidence_url = f"{self.callback_receiver_url}/evidence?token={token}"
                resp = self.session.get(evidence_url, timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    callbacks = data.get("callbacks", [])
                    if callbacks:
                        return {
                            "received": True,
                            "count": len(callbacks),
                            "total_callbacks": data.get("total_callbacks", len(callbacks)),
                            "unique_tokens": data.get("unique_tokens", 1),
                            "details": callbacks,
                            "poll_duration_s": round(time.time() - start_time, 3)
                        }
            except Exception:
                pass

            time.sleep(CALLBACK_POLL_INTERVAL)

        return {
            "received": False,
            "count": 0,
            "details": [],
            "poll_duration_s": round(time.time() - start_time, 3)
        }

    def scan(self, endpoint: str, parameter: str, mode: str = "vulnerable") -> List[Dict[str, Any]]:
        findings = []
        token = self._generate_test_token()
        probe = self.payload_generator.generate_category_i(token=token)
        target_callback_url = probe["payload"]

        print(f"\n  [BLIND-OOB] Testing parameter '{parameter}' with tracking token: {token} (Mode: {mode.upper()})")

        params = {parameter: target_callback_url}
        if mode == "secure":
            params["mode"] = "secure"

        # 1. Dispatch request through public application
        response = self.client.get(endpoint, params=params)

        # 2. Perform bounded polling on the dedicated callback receiver
        poll_result = self._poll_evidence(token)

        is_detected = poll_result["received"]
        confidence = "LAB_CONFIRMED" if is_detected else "NONE"
        evidence = []
        verification_method = "Out-of-Band Callback Correlation"
        test_outcome = "POSITIVE" if is_detected else "NEGATIVE"

        if is_detected:
            first_callback = poll_result["details"][0]
            evidence.append(
                f"Out-of-Band callback confirmed! Received {poll_result['count']} request(s) "
                f"with token '{token}' from IP {first_callback.get('source_ip')} "
                f"at {first_callback.get('timestamp')} (Poll time: {poll_result['poll_duration_s']}s)."
            )
            if first_callback.get("is_duplicate"):
                evidence.append("Duplicate callback request detected and flagged by evidence store.")
            print(f"    [+] DETECTED: Blind OOB SSRF confirmed via callback token {token}")
        else:
            evidence.append(
                f"No Out-of-Band callback received for token '{token}' within {CALLBACK_POLL_TIMEOUT}s timeout."
            )
            print(f"    [-] Clean: No OOB callback received for token {token}")

        finding = self.response_analyzer.create_finding(
            category="BLIND_OOB_SSRF",
            technique="Blind / Out-of-Band",
            endpoint=endpoint,
            parameter=parameter,
            payload=target_callback_url,
            response=response,
            detected=is_detected,
            confidence=confidence,
            evidence=evidence,
            verification_method=verification_method,
            extra_metadata={
                "token": token,
                "poll_result": poll_result,
                "probe_id": probe["id"],
                "test_outcome": test_outcome,
                "mode": mode
            }
        )

        findings.append(finding)
        time.sleep(SCAN_DELAY)
        return findings

    def close(self):
        self.session.close()
