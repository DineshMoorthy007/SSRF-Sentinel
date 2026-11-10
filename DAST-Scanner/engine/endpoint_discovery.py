from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit
import time

from config import TARGET_URL, SCAN_DELAY


class PageParser(HTMLParser):

    def __init__(self):

        super().__init__()

        self.links = []
        self.forms = []

        self.current_form = None

    def handle_starttag(self, tag, attrs):

        attributes = dict(attrs)

        # Extract hyperlinks
        if tag == "a":

            href = attributes.get("href")

            if href:
                self.links.append(href)

        # Extract forms
        elif tag == "form":

            self.current_form = {

                "action": attributes.get("action", ""),
                "method": attributes.get("method", "GET").upper(),
                "parameters": []

            }

        # Extract form parameters
        elif tag in ("input", "textarea", "select"):

            if self.current_form:

                name = attributes.get("name")

                if name:

                    self.current_form["parameters"].append({

                        "name": name,

                        "type": attributes.get("type", tag)

                    })

    def handle_endtag(self, tag):

        if tag == "form" and self.current_form:

            self.forms.append(self.current_form)

            self.current_form = None


class EndpointDiscovery:

    def __init__(self, client):

        self.client = client

        self.base_url = TARGET_URL.rstrip("/")

        self.discovered = {}

        self.visited = set()

        self.max_pages = 20

        self.delay = SCAN_DELAY

    def normalize_url(self, url):

        absolute_url = urljoin(self.base_url + "/", url)

        parsed = urlsplit(absolute_url)

        target = urlsplit(self.base_url)

        # Restrict crawling to the configured target
        if (
            parsed.scheme != target.scheme
            or parsed.hostname != target.hostname
            or parsed.port != target.port
            or parsed.username is not None
            or parsed.password is not None
        ):

            return None

        return urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            ""
        ))

    def extract_path(self, url):

        parsed = urlsplit(url)

        return parsed.path + (
            "?" + parsed.query if parsed.query else ""
        )

    def discover(self):

        print("\n[INFO] Starting endpoint discovery...")

        queue = [self.base_url + "/"]

        while queue and len(self.visited) < self.max_pages:

            current_url = queue.pop(0)

            normalized = self.normalize_url(current_url)

            if not normalized or normalized in self.visited:

                continue

            self.visited.add(normalized)

            path = self.extract_path(normalized)

            print(f"[SCAN] Visiting: {path}")

            response = self.client.get(path)

            if response is None:

                continue

            if response.status_code == 404:

                continue

            endpoint = {

                "path": urlsplit(normalized).path,

                "status": response.status_code,

                "method": "GET",

                "parameters": [],

                "source": "crawl"

            }

            # Extract query parameter names
            query = urlsplit(normalized).query

            if query:

                from urllib.parse import parse_qsl

                endpoint["parameters"].extend(
                    name for name, _ in parse_qsl(query)
                )

            content_type = response.headers.get(
                "Content-Type", ""
            )

            if "text/html" in content_type.lower():

                parser = PageParser()

                parser.feed(response.text)

                # Process hyperlinks
                for link in parser.links:

                    discovered_url = self.normalize_url(
                        link
                    )

                    if discovered_url:

                        if discovered_url not in self.visited:

                            queue.append(discovered_url)

                # Process forms
                for form in parser.forms:

                    action = self.normalize_url(
                        form["action"] or normalized
                    )

                    if not action:

                        continue

                    action_path = self.extract_path(action)

                    form_endpoint = {

                        "path": urlsplit(action).path,

                        "status": None,

                        "method": form["method"],

                        "parameters": [
                            item["name"]
                            for item in form["parameters"]
                        ],

                        "source": "html_form"

                    }

                    key = (
                        form_endpoint["path"],
                        form_endpoint["method"]
                    )

                    self.discovered[key] = form_endpoint

                    if action not in self.visited:

                        queue.append(action)

            key = (endpoint["path"], "GET")

            if key in self.discovered:

                existing = self.discovered[key]

                existing["status"] = endpoint["status"]

                existing["parameters"] = list(
                    set(
                        existing["parameters"] +
                        endpoint["parameters"]
                    )
                )

            else:

                self.discovered[key] = endpoint

            time.sleep(self.delay)

        print("\n[INFO] Endpoint discovery completed.")

        return list(self.discovered.values())

    def enumerate_paths(self):

        from config import DISCOVERY_PATHS

        print("\n[INFO] Starting path enumeration...")

        for path in DISCOVERY_PATHS:

            candidate_url = self.normalize_url(
                self.base_url + path
            )

            if candidate_url in self.visited:
                continue

            print(f"[CHECK] Testing path: {path}")

            response = self.client.get(path)

            if response is None:
                continue

            if response.status_code == 404:
                continue

            endpoint = {

                "path": path,

                "status": response.status_code,

                "method": "GET",

                "parameters": [],

                "source": "path_enumeration"

            }

            key = (path, "GET")

            self.discovered.setdefault(key, endpoint)

            print(
                f"[+] Endpoint found: {path} "
                f"({response.status_code})"
            )

            time.sleep(self.delay)

        print("[INFO] Path enumeration completed.")

    def display_results(self, endpoints):

        print("\n" + "=" * 65)

        print("             DISCOVERED ENDPOINTS")

        print("=" * 65)

        if not endpoints:

            print("[WARNING] No endpoints discovered.")

            return

        for endpoint in endpoints:

            print(f"\n[+] Endpoint : {endpoint['path']}")

            print(f"    Method   : {endpoint['method']}")

            print(f"    Status   : {endpoint['status']}")

            print(f"    Source   : {endpoint['source']}")

            if endpoint["parameters"]:

                print(
                    f"    Parameters: {endpoint['parameters']}"
                )

        print("\n" + "=" * 65)

        print(f"[SUCCESS] Total discovered entries: {len(endpoints)}")