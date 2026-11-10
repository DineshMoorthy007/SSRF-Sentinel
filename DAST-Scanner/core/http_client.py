import requests

from urllib.parse import urlsplit

from config import (
    TARGET_URL,
    REQUEST_TIMEOUT,
    ALLOWED_HOST,
    ALLOWED_PORT
)


class HTTPClient:

    def __init__(self):

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": "SSRF-Sentinel/1.0",
            "Accept": "*/*"
        })

        self.base_url = TARGET_URL.rstrip("/")

    def _validate_target(self, path):

        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Invalid endpoint path")

        parsed = urlsplit(self.base_url)

        if (
            parsed.hostname != ALLOWED_HOST
            or parsed.port != ALLOWED_PORT
        ):
            raise ValueError("Target is outside the local test scope")

    def get(self, path, params=None):

        self._validate_target(path)

        url = self.base_url + path

        try:

            response = self.session.get(
                url,
                params=params,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False
            )

            return response

        except requests.exceptions.Timeout:

            print("[ERROR] Request timed out.")

        except requests.exceptions.ConnectionError:

            print("[ERROR] Unable to connect to target.")

        except requests.exceptions.RequestException as error:

            print(f"[ERROR] HTTP request failed: {error}")

        return None

    def close(self):

        self.session.close()