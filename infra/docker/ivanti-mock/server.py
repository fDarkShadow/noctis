"""Mock Ivanti Connect Secure — CVE-2023-46805 auth bypass behaviour."""
import json
import os

VULN_MODE = os.environ.get("IVANTI_MODE", "patched") == "vuln"

SYSTEM_INFO = json.dumps({
    "build": "22.5.0.0",
    "system-information": "Ivanti Connect Secure 22.5R2",
    "software-inventory": ["ivanti-ics-22.5.0.0", "ivanti-policy-secure"],
}).encode()

ADMIN_OPTIONS = json.dumps({
    "poll_interval": 300,
    "block_message": "Access denied by policy",
    "options": {},
}).encode()

IVANTI_ROOT = b'<html><head><title>Ivanti Connect Secure</title></head><body><a href="welcome.cgi?p=logo">Login</a></body></html>'


def _handler_class():
    from http.server import BaseHTTPRequestHandler

    class IvantiHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            raw = self.path

            if ".." in raw:
                if not VULN_MODE:
                    self._send(401, b'{"message":"Permission Denied"}')
                    return
                # Vulnerable: serve the traversal target based on what the URL is trying to reach
                if "system-information" in raw:
                    self._send(200, SYSTEM_INFO)
                elif "admin/options" in raw:
                    self._send(200, ADMIN_OPTIONS)
                else:
                    self._send(404, b'{"message":"Not Found"}')
                return

            if raw == "/" or raw.startswith("/?"):
                self._send(200, IVANTI_ROOT, "text/html")
                return

            if raw.startswith("/api/v1/"):
                self._send(401, b'{"message":"Authentication required"}')
                return

            self._send(404, b'{"message":"Not Found"}')

    return IvantiHandler


def _make_https_server(handler, port):
    import ssl
    from http.server import HTTPServer
    srv = HTTPServer(("0.0.0.0", port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    import threading
    from http.server import HTTPServer
    handler = _handler_class()
    mode = "vuln" if VULN_MODE else "patched"
    http_srv = HTTPServer(("0.0.0.0", 80), handler)
    https_srv = _make_https_server(handler, 443)
    print(f"Ivanti Connect Secure mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
