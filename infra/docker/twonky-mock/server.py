#!/usr/bin/env python3
"""Mock for CVE-2025-13315 — Twonky Server (CVSS 10.0)
Ported from OpenVAS NASL 2025/lynxtechnology/gb_twonky_auth_bypass_vuln_nov25_active.nasl (GPL-2.0-only, Greenbone Community Feed)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("TWONKY_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("utf-8", "replace") if n else ""

    def do_GET(self):
        if VULN_MODE and self.path == "/nmc/rpc/log_getfile":
            self._send(200, "LOG_SYSTEM\n2025-11-01 12:00:00 twonkyserver started\n2025-11-01 12:00:01 scanning /media\n")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
