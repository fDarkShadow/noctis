#!/usr/bin/env python3
"""Mock for CVE-2024-8956 — PTZOptics PT30X-SDI/NDI cameras (CVSS 9.4)
Ported from OpenVAS NASL 2025/ptzoptics/gb_camera_mult_vuln_sep24_active.nasl (GPL-2.0-only, Greenbone Community Feed)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PTZOPTICS_MODE", "patched") == "vuln"


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
        if VULN_MODE and self.path == "/cgi-bin/param.cgi?get_system_conf":
            body = ('devname="PTZOptics"\n'
                    'userid="admin"\n'
                    'userpasswd="5f4dcc3b5aa765d61d8327deb882cf99"\n'
                    'httpport="80"\n')
            self._send(200, body)
        else:
            self._send(401, "Unauthorized")

    def do_POST(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
