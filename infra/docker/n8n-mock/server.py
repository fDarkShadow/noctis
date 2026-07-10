#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("N8N_MODE", "patched") == "vuln"

# base64 of {"n8n@version":"1.118.0"} — vulnerable (< 1.120.4)
VULN_VERSION = "1.118.0"
VULN_B64 = "eyJuOG5AdmVyc2lvbiI6IjEuMTE4LjAifQ=="

# base64 of {"n8n@version":"1.122.0"} — patched (>= 1.122.0)
PATCHED_VERSION = "1.122.0"
PATCHED_B64 = "eyJuOG5AdmVyc2lvbiI6IjEuMTIyLjAifQ=="

def make_page(b64):
    return (
        "<html><head>"
        "<title>n8n.io - Workflow Automation</title>"
        f'<meta name="n8n:config:sentry" content="{b64}">'
        "</head><body>n8n login</body></html>"
    )

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html", version=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if version:
            self.send_header("X-n8n-Version", version)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/signin", "/"):
            if VULN_MODE:
                self._send(200, make_page(VULN_B64), version=VULN_VERSION)
            else:
                self._send(200, make_page(PATCHED_B64), version=PATCHED_VERSION)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self._send(404, "Not found")

def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv

if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
