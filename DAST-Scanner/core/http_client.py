import requests
from urllib.parse import urlsplit

from config import (
    TARGET_URL,
    REQUEST_TIMEOUT,
    ALLOWED_HOST,
    ALLOWED_PORT
)


class HTTPClient:
    """
    Scope-constrained HTTP client for SSRF Sentinel.
    Guarantees that all outgoing requests from the scanner are strictly bound
    to the authorized public target application (127.0.0.1:8080).
    """

    def __init__(self, base_url: str = None):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SSRF-Sentinel/2.0 (Security Scanner)",
            "Accept": "*/*"
        })
        self.base_url = (base_url or TARGET_URL).rstrip("/")

    def _validate_target(self, path: str):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError(f"Invalid endpoint path: {path}")

        parsed = urlsplit(self.base_url)
        if parsed.hostname != ALLOWED_HOST or parsed.port != ALLOWED_PORT:
            raise ValueError(f"Target {self.base_url} is outside authorized local test scope ({ALLOWED_HOST}:{ALLOWED_PORT})")

    def get(self, path: str, params: dict = None, headers: dict = None, timeout: float = None):
        self._validate_target(path)
        url = self.base_url + path
        req_timeout = timeout if timeout is not None else REQUEST_TIMEOUT

        try:
            req_headers = {}
            if headers:
                req_headers.update(headers)

            response = self.session.get(
                url,
                params=params,
                headers=req_headers if req_headers else None,
                timeout=req_timeout,
                allow_redirects=False
            )
            return response

        except requests.exceptions.Timeout:
            return None

        except requests.exceptions.ConnectionError:
            return None

        except requests.exceptions.RequestException:
            return None

    def post(self, path: str, data: dict = None, json_data: dict = None, headers: dict = None, timeout: float = None):
        self._validate_target(path)
        url = self.base_url + path
        req_timeout = timeout if timeout is not None else REQUEST_TIMEOUT

        try:
            req_headers = {}
            if headers:
                req_headers.update(headers)

            response = self.session.post(
                url,
                data=data,
                json=json_data,
                headers=req_headers if req_headers else None,
                timeout=req_timeout,
                allow_redirects=False
            )
            return response

        except requests.exceptions.RequestException:
            return None

    def close(self):
        self.session.close()
