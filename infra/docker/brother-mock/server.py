#!/usr/bin/env python3
# Mock for CVE-2017-7588 — Brother Devices web authorization bypass.
# Vuln mode: POST /general/status.html issues an unauthenticated AuthCookie
# session cookie. Patched mode: the endpoint requires authentication (401),
# so no AuthCookie is set and the detection pattern is absent.
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BROTHER_MODE", "patched") == "vuln"
CERT_DIR = os.environ.get("CERT_DIR", "/certs")
PORT_HTTP = int(os.environ.get("PORT_HTTP", "80"))
PORT_HTTPS = int(os.environ.get("PORT_HTTPS", "443"))

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items(): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        if self.path == "/general/status.html":
            if VULN_MODE:
                self._send(200, "<html><body>Status</body></html>",
                           extra_headers={"Set-Cookie": "AuthCookie=a1b2c3d4e5f6; path=/"})
            else:
                self._send(401, "Authentication required")
        else:
            self._send(404, "Not found")
    def do_GET(self):
        self._send(404, "Not found")

def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(CERT_DIR, "server.crt"), os.path.join(CERT_DIR, "server.key"))
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv

if __name__ == "__main__":
    if PORT_HTTPS:
        threading.Thread(target=lambda: _make_https_server(PORT_HTTPS).serve_forever(), daemon=True).start()
    if PORT_HTTP:
        HTTPServer(("0.0.0.0", PORT_HTTP), Handler).serve_forever()
    else:
        threading.Event().wait()
