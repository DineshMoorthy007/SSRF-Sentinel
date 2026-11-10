import time
import uuid
import requests
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
    Tests whether the server generates an external HTTP request to a dedicated local callback listener (port 8090).
    Uses cryptographic tokens and bounded polling to prevent cross-test attribution.
    """

    def __init__(self, client, response_analyzer=None, payload_generator=None, callback_url=None):
        self.client = client
        self.response_analyzer = response_analyzer or ResponseAnalyzer()
        self.payload_generator = payload_generator or PayloadGenerator()
        self.callback_receiver_url = (callback_url or CALLBACK_RECEIVER_URL).rstrip("/")
        self.session = requests.Session()

    def _generate_test_token(self) -> str:
        """Requests a token from the callback server or falls back to local high-entropy token."""
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
                            "details": callbacks,
                            "poll_duration_s": round(time.time() - start_time, 3)
                        }
            except Exception as e:
                # Callback server might be briefly busy or starting up
                pass

            time.sleep(CALLBACK_POLL_INTERVAL)

        return {
            "received": False,
            "count": 0,
            "details": [],
            "poll_duration_s": round(time.time() - start_time, 3)
        }

    def scan(self, endpoint: str, parameter: str) -> list:
        findings = []
        token = self._generate_test_token()
        probe = self.payload_generator.generate_oob_payload(token=token)
        target_callback_url = probe["payload"]

        print(f"\n  [BLIND-OOB] Testing parameter '{parameter}' with tracking token: {token}")

        # 1. Dispatch request through public application
        response = self.client.get(
            endpoint,
            params={parameter: target_callback_url}
        )

        # 2. Perform bounded polling on the dedicated callback receiver
        poll_result = self._poll_evidence(token)

        is_detected = poll_result["received"]
        confidence = "LAB_CONFIRMED" if is_detected else "NONE"
        evidence = []
        verification_method = "Out-of-Band Callback Correlation"

        if is_detected:
            first_callback = poll_result["details"][0]
            evidence.append(
                f"Out-of-Band callback confirmed! Received {poll_result['count']} request(s) "
                f"with token '{token}' from IP {first_callback.get('source_ip')} "
                f"at {first_callback.get('timestamp')} (Poll time: {poll_result['poll_duration_s']}s)."
            )
            print(f"    [+] DETECTED: Blind OOB SSRF confirmed via callback token {token}")
        else:
            evidence.append(
                f"No callback received on {self.callback_receiver_url} within "
                f"{poll_result['poll_duration_s']}s for token '{token}'."
            )
            print(f"    [-] Clean: No outbound callback received for token {token}")

        finding = self.response_analyzer.create_finding(
            category="BLIND_OOB_SSRF",
            technique="Blind / Out-of-Band SSRF",
            endpoint=endpoint,
            parameter=parameter,
            payload=target_callback_url,
            response=response,
            detected=is_detected,
            confidence=confidence,
            evidence=evidence,
            verification_method=verification_method,
            extra_metadata={
                "oob_token": token,
                "callback_receiver": self.callback_receiver_url,
                "callback_count": poll_result["count"],
                "callback_events": poll_result["details"]
            }
        )

        findings.append(finding)
        time.sleep(SCAN_DELAY)
        return findings

    def close(self):
        self.session.close()

