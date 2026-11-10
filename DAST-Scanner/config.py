PROJECT_NAME = "SSRF Sentinel"
VERSION = "2.0"

# Public target application (scanned entrypoint)
TARGET_URL = "http://127.0.0.1:8080"

# Internal simulated service
INTERNAL_SERVICE_URL = "http://127.0.0.1:8081"

# Dedicated Out-of-Band (OOB) callback receiver
CALLBACK_RECEIVER_URL = "http://127.0.0.1:8090"

# Request parameters
REQUEST_TIMEOUT = 10
MAX_REDIRECTS = 3
SCAN_DELAY = 0.3

# Verification markers for deterministic test verification
VERIFICATION_MARKER = "SSRF_SENTINEL_INTERNAL_ACCESS_2026"
INBAND_MARKER = "SSRF_SENTINEL_INBAND_FULL_ACCESS"
LIMITED_HEADER_MARKER = "SSRF_HEADER_ONLY_FLAG"
TIME_FAST_MARKER = "SSRF_TIME_FAST_IMMEDIATE"
TIME_DELAYED_MARKER = "SSRF_TIME_DELAYED_SUCCESS"
BOOLEAN_TRUE_MARKER = "SSRF_BOOLEAN_TRUE_VERIFIED"

# Out-of-Band (OOB) callback polling settings
CALLBACK_POLL_TIMEOUT = 5.0
CALLBACK_POLL_INTERVAL = 0.5
CALLBACK_MAX_RETRIES = 6

# Time-Based SSRF thresholds
TIME_DELAY_SECONDS = 2.0
TIME_DELTA_THRESHOLD = 1.2
TIME_TEST_ITERATIONS = 3

# Boolean-Based SSRF parameters
BOOLEAN_TEST_ITERATIONS = 2
BOOLEAN_LENGTH_DIFF_THRESHOLD = 50

# Public application endpoints
INITIAL_ENDPOINTS = [
    "/",
    "/health",
    "/fetch"
]

# Internal test resources
INTERNAL_TEST_PATH = "/internal/secret"
INTERNAL_STATUS_PATH = "/internal/status"

# Scanner target scope restrictions
ALLOWED_HOST = "127.0.0.1"
ALLOWED_PORT = 8080
ALLOWED_PORTS = [8080, 8081, 8090]

# Endpoint discovery paths
DISCOVERY_PATHS = [
    "/health",
    "/fetch",
    "/robots.txt",
    "/sitemap.xml",
    "/api",
    "/api/v1"
]
