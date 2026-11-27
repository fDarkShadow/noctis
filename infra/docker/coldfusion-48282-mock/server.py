#!/usr/bin/env python3
"""Mock Adobe ColdFusion — CVE-2026-48282 RDS unauthenticated file write.

Vuln mode (RDS auth disabled): a POST to /CFIDE/main/ide.cfm?ACTION=FILEIO is
accepted without authentication and returns the RDS accept prefix (1:2:).
Patched mode: RDS authentication is required → 403.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("COLDFUSION_MODE", "patched") == "vuln"
VERSION = "2023.20" if VULN_MODE else "2023.21"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "ColdFusion")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/CFIDE/main/ide.cfm":
            self._send(200, f"ColdFusion RDS Server {VERSION}")
            return
        self._send(404, "Not found")

    def do_POST(self):
        path = self.path  # keep ?ACTION=FILEIO
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)

        if path == "/CFIDE/main/ide.cfm?ACTION=FILEIO":
            if VULN_MODE:
                # RDS accept prefix (1:2:) + echoed path = write accepted unauth.
                self._send(200, "1:2:/tmp/noctis-probe-test.txt")
            else:
                self._send(403, "RDS authentication required")
            return

        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
