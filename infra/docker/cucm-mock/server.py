#!/usr/bin/env python3
"""Mock Cisco Unified CM — CVE-2026-20230 WebDialer SSRF/RCE exposure.

Both modes serve the /cucm-uds/version fingerprint endpoint. Only the vuln
mode exposes the WebDialer service (/WebDialer/ → 200); the patched mode has
it disabled (404).
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("CUCM_MODE", "patched") == "vuln"
CUCM_VERSION = "14.0.1.13900-100" if VULN_MODE else "14.0.1.13900-200"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/cucm-uds/version":
            self._send(
                200,
                f'<?xml version="1.0"?><CUCMVersion><version>{CUCM_VERSION}</version></CUCMVersion>',
                "application/xml",
            )
            return

        if path == "/WebDialer/":
            if VULN_MODE:
                self._send(200, "Cisco WebDialer - NOCTIS_CUCM_WEBDIALER_ACCESSIBLE", "text/html")
            else:
                self._send(404, "Service not found")
            return

        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
