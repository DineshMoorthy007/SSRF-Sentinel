PROJECT_NAME = "SSRF Sentinel"
VERSION = "2.1"

# Target Environment Endpoints (Conforms strictly to 127.0.0.1 scope)
TARGET_URL = "http://127.0.0.1:8080"
INTERNAL_SERVICE_URL = "http://127.0.0.1:8081"
CALLBACK_RECEIVER_URL = "http://127.0.0.1:8090"

# Timing and Network Limits
REQUEST_TIMEOUT = 10.0
FAST_REQUEST_TIMEOUT = 3.0
MAX_REDIRECTS = 3
SCAN_DELAY = 0.2

# Cryptographic and Verification Markers
VERIFICATION_MARKER = "SSRF_SENTINEL_INTERNAL_ACCESS_2026"
INBAND_MARKER = "SSRF_SENTINEL_INBAND_FULL_ACCESS"
LIMITED_HEADER_MARKER = "SSRF_HEADER_ONLY_FLAG"
TIME_FAST_MARKER = "SSRF_TIME_FAST_IMMEDIATE"
TIME_DELAYED_MARKER = "SSRF_TIME_DELAYED_SUCCESS"
BOOLEAN_TRUE_MARKER = "SSRF_BOOLEAN_TRUE_VERIFIED"
REDIRECT_MARKER = "SSRF_REDIRECT_DISPATCHED"

# Out-of-Band (OOB) Polling Configuration
CALLBACK_POLL_TIMEOUT = 4.0
CALLBACK_POLL_INTERVAL = 0.4
CALLBACK_MAX_RETRIES = 6

# Time-Based SSRF Calibration
TIME_DELAY_SECONDS = 2.0
TIME_DELTA_THRESHOLD = 1.2
TIME_TEST_ITERATIONS = 3

# Boolean-Based SSRF Calibration
BOOLEAN_TEST_ITERATIONS = 2
BOOLEAN_LENGTH_DIFF_THRESHOLD = 50

# Public application known endpoints
INITIAL_ENDPOINTS = [
    "/",
    "/health",
    "/fetch",
    "/fetch-secure",
    "/redirect"
]

# Internal test resources on Port 8081
INTERNAL_TEST_PATH = "/internal/secret"
INTERNAL_STATUS_PATH = "/internal/status"
INTERNAL_ADMIN_PATH = "/internal/admin/config"

# Scope Enforcements
ALLOWED_HOST = "127.0.0.1"
ALLOWED_PORT = 8080
ALLOWED_PORTS = [8080, 8081, 8090]

# Crawler Discovery Paths
DISCOVERY_PATHS = [
    "/health",
    "/fetch",
    "/fetch-secure",
    "/redirect",
    "/robots.txt",
    "/sitemap.xml",
    "/api",
    "/api/v1"
]
