#!/usr/bin/env python3
"""Mock for CVE-2024-3721 — TBK DVR-4104 / DVR-4216 (CVSS 10.0)
Ported from OpenVAS NASL 2024/tbk/gb_dvr_cmd_inj_vuln_apr24_active.nasl (GPL-2.0-only, Greenbone Community Feed)."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("TBK_MODE", "patched") == "vuln"


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
        if self.path == "/login.rsp":
            self._send(200, "<html><body>DVR Login</body></html>", ct="text/html")
        elif VULN_MODE and self.path.startswith("/device.rsp") and "mdc=" in self.path:
            self._send(200, "uid=0(root) gid=0(root) groups=0(root)\n")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
