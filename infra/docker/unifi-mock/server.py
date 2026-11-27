#!/usr/bin/env python3
"""Mock Ubiquiti UniFi OS Server — CVE-2026-34910 RCE chain (path-traversal probe).

Vuln mode: the raw /api/auth/validate-sso/../../../proxy/... path is routed to
the internal package-update endpoint (200). Python's BaseHTTPRequestHandler
leaves self.path un-normalised, so the ../ segments are present verbatim.
Patched mode: any path containing ../ is rejected (400) before routing.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("UNIFI_MODE", "patched") == "vuln"

LOGIN_BODY = (
    "<html><head><title>UniFi OS</title></head>"
    "<body>UniFi Network Application</body></html>"
)
PKG_ENDPOINT = "/proxy/users/api/v2/ucs/update/latest_package"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-UniFi-OS", "5.0.6" if VULN_MODE else "5.0.8")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        raw = self.path  # un-normalised

        # Patched gateway strips/rejects traversal before routing.
        if not VULN_MODE and "../" in raw:
            self._send(400, '{"error":"Bad Request"}', "application/json")
            return

        # Vulnerable: the traversal reaches the internal package-update service.
        if PKG_ENDPOINT in raw:
            if VULN_MODE:
                self._send(200, '{"ok":true,"NOCTIS_UNIFI_TRAVERSAL":"confirmed"}',
                           "application/json")
            else:
                self._send(400, '{"error":"Bad Request"}', "application/json")
            return

        path = raw.split("?", 1)[0]
        if path in ("/login", "/"):
            self._send(200, LOGIN_BODY, "text/html")
            return

        self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
