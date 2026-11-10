import http.server
import socketserver
import threading
import time
import urllib.parse
import json
import uuid
from datetime import datetime, timezone


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockPublicHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default noisy console logs

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"running","service":"Public Application"}')
        elif path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            html = """<!DOCTYPE html><html><body>
            <form action="/fetch" method="GET">
                <input type="url" name="url" required>
                <button type="submit">Fetch</button>
            </form>
            </body></html>"""
            self.wfile.write(html.encode("utf-8"))
        elif path == "/fetch":
            if "url" not in query:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing URL parameter")
                return

            target_url = query["url"][0]
            # Validate destination
            parsed_dest = urllib.parse.urlsplit(target_url)
            if parsed_dest.hostname not in ("127.0.0.1", "localhost") or parsed_dest.port not in (8080, 8081, 8090):
                self.send_response(403)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Destination host or port not permitted in local test environment")
                return

            import requests
            try:
                # Forward to internal target with bounded timeout
                resp = requests.get(target_url, timeout=8)
                self.send_response(resp.status_code)
                for h_name, h_val in resp.headers.items():
                    if h_name.startswith("X-") or h_name == "Content-Type":
                        self.send_header(h_name, h_val)
                self.end_headers()
                self.wfile.write(resp.content)
            except Exception as e:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(f"Internal test request failed: {e}".encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


class MockInternalHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/internal/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"service":"Internal Test Service","status":"Running","environment":"Local Testing"}')
        elif path == "/internal/secret":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Internal-Service", "SSRF-Sentinel-Mock")
            self.end_headers()
            self.wfile.write(b'{"resource":"Internal Test Resource","classification":"Restricted","verification_marker":"SSRF_SENTINEL_INTERNAL_ACCESS_2026"}')
        elif path == "/internal/admin/config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-Internal-Service", "SSRF-Sentinel-Core")
            self.send_header("X-Resource-ID", "admin-config-vault")
            self.end_headers()
            self.wfile.write(b'{"service":"Internal Admin Core","version":"1.1-enterprise","database_uri":"postgresql://sentinel_admin:p@ssw0rd@127.0.0.1:5432/core_db","admin_session_key":"ADMIN_KEY_784920193482","verification_marker":"SSRF_SENTINEL_INBAND_FULL_ACCESS"}')
        elif path == "/internal/limited/status-only":
            self.send_response(204)
            self.end_headers()
        elif path == "/internal/limited/header-only":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-Internal-Status", "ACTIVE")
            self.send_header("X-Response-Type", "HEADER_ONLY")
            self.send_header("X-Internal-Marker", "SSRF_HEADER_ONLY_FLAG")
            self.end_headers()
        elif path == "/internal/limited/truncated":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"success","leak":"SSRF_SECRET_SEGMENT_PARTIAL_DATA_REDA')
        elif path == "/internal/limited/generic":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"success","message":"Internal request processed successfully"}')
        elif path == "/internal/limited/suppressed":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"acknowledged","content_filter":"ACTIVE","filtered_data":"[CONTENT_SUPPRESSED_BY_POLICY]"}')
        elif path == "/internal/fast":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"endpoint":"/internal/fast","status":"success","delay_ms":0,"execution":"immediate","verification_marker":"SSRF_TIME_FAST_IMMEDIATE"}')
        elif path == "/internal/delayed":
            delay_sec = 2.0
            if "ms" in query:
                try:
                    delay_sec = min(5000, max(0, int(query["ms"][0]))) / 1000.0
                except Exception:
                    pass
            time.sleep(delay_sec)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = json.dumps({
                "endpoint": "/internal/delayed",
                "status": "success",
                "delay_ms": int(delay_sec * 1000),
                "execution": "delayed",
                "verification_marker": "SSRF_TIME_DELAYED_SUCCESS"
            })
            self.wfile.write(resp.encode("utf-8"))
        elif path == "/internal/check":
            cond = query.get("condition", [""])[0]
            if cond == "true":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-SSRF-Evaluation", "TRUE")
                self.end_headers()
                data = json.dumps({
                    "endpoint": "/internal/check",
                    "condition": True,
                    "evaluation": "MATCH_TRUE",
                    "result": "CONDITION_VERIFIED_SUCCESSFUL",
                    "verification_marker": "SSRF_BOOLEAN_TRUE_VERIFIED",
                    "padding": "X" * 100
                })
                self.wfile.write(data.encode("utf-8"))
            elif cond == "false":
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-SSRF-Evaluation", "FALSE")
                self.end_headers()
                data = json.dumps({"endpoint": "/internal/check", "condition": False, "evaluation": "MATCH_FALSE"})
                self.wfile.write(data.encode("utf-8"))
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"Invalid condition"}')
        else:
            self.send_response(404)
            self.end_headers()


class MockCallbackHandler(http.server.BaseHTTPRequestHandler):
    lock = threading.Lock()
    callbacks = []

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"running","service":"SSRF Callback Receiver","port":8090}')
        elif path == "/token/generate":
            token = f"ssrf_tok_{uuid.uuid4().hex[:16]}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            resp = json.dumps({
                "status": "success",
                "token": token,
                "callback_url": f"http://127.0.0.1:8090/callback?token={token}"
            })
            self.wfile.write(resp.encode("utf-8"))
        elif path == "/callback":
            token = query.get("token", [""])[0]
            with self.lock:
                self.callbacks.append({
                    "token": token,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "method": "GET",
                    "path": self.path,
                    "source_ip": self.client_address[0]
                })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"received","message":"Callback acknowledged"}')
        elif path == "/evidence":
            token = query.get("token", [""])[0]
            with self.lock:
                filtered = [c for c in self.callbacks if not token or c["token"] == token]
                resp = json.dumps({
                    "service": "SSRF Callback Evidence Store",
                    "filter_token": token,
                    "count": len(filtered),
                    "callbacks": filtered
                })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path in ("/evidence/reset", "/reset"):
            with self.lock:
                self.callbacks.clear()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"cleared","message":"All callback evidence cleared"}')
        else:
            self.do_GET()


class TargetServerCluster:
    def __init__(self):
        self.public_server = ThreadingHTTPServer(("127.0.0.1", 8080), MockPublicHandler)
        self.internal_server = ThreadingHTTPServer(("127.0.0.1", 8081), MockInternalHandler)
        self.callback_server = ThreadingHTTPServer(("127.0.0.1", 8090), MockCallbackHandler)
        self.threads = []

    def start(self):
        for server in (self.public_server, self.internal_server, self.callback_server):
            t = threading.Thread(target=server.serve_forever, daemon=True)
            t.start()
            self.threads.append(t)
        time.sleep(0.3)
        print("[TEST HARNESS] All 3 servers active on 8080, 8081, 8090.")

    def stop(self):
        self.public_server.shutdown()
        self.internal_server.shutdown()
        self.callback_server.shutdown()
        self.public_server.server_close()
        self.internal_server.server_close()
        self.callback_server.server_close()
        print("[TEST HARNESS] All 3 servers stopped.")


if __name__ == "__main__":
    cluster = TargetServerCluster()
    cluster.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        cluster.stop()

