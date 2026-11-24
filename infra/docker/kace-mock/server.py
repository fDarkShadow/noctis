#!/usr/bin/env python3
"""Mock Quest KACE SMA (K1000) — CVE-2025-32975 SSO auth bypass.

Both modes expose the X-Kace-Appliance: K1000 header (fingerprint works on
either). Only the vuln mode hands back a session token on the SSO login
endpoint without authentication; the patched mode returns 403.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("KACE_MODE", "patched") == "vuln"
KACE_VERSION = "13.0.300" if VULN_MODE else "13.0.400"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        # Present on every KACE K1000 response.
        self.send_header("X-Kace-Appliance", "K1000")
        self.send_header("X-Kace-Version", KACE_VERSION)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/ams/shared/api/security/login":
            if VULN_MODE:
                self._send(
                    200,
                    '{"sessionId":"NOCTIS_KACE_SSO_BYPASSED",'
                    '"token":"kace-bypass-token-confirmed","admin":true}',
                    "application/json",
                )
            else:
                self._send(403, '{"error":"Authentication required"}', "application/json")
            return

        if path == "/":
            self._send(200, "<html><title>KACE SMA</title><body>K1000</body></html>", "text/html")
            return

        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
