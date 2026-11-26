#!/usr/bin/env python3
"""Mock PAN-OS ZTP management interface — CVE-2024-0012 (auth bypass via X-PAN-AUTHCHECK)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PANOS_ZTP_MODE", "patched") == "vuln"

# Realistic ZTP source-map response — matches both patterns in the feed:
#   "Zero Touch Provisioning" and "mainui\.javascript"
VULN_BODY = (
    '{"version":3,"sources":["mainui.javascript"],'
    '"mappings":"AAAA","names":[],'
    '"x-comment":"Zero Touch Provisioning management plane"}'
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/php/ztp_gate.php/.js.map":
            if VULN_MODE and self.headers.get("X-PAN-AUTHCHECK", "").lower() == "off":
                self._send(200, VULN_BODY, ct="application/json")
            else:
                # Patched: auth middleware ignores the bypass header
                self._send(302, "Redirecting", ct="text/html")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
