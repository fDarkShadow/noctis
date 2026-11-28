#!/usr/bin/env python3
"""Mock for CVE-2021-33045 — Dahua IPC/VTH/VTO authentication bypass (CVSS 9.8).

Vuln mode gates acceptance on the bypass identity (loginType "Loopback" with
ipAddr 127.0.0.1): only that crafted login is accepted without valid credentials
and returns an authenticated session id. A normal bad-credential login (any other
loginType) still fails on the vuln mock, as on real firmware. Patched mode rejects
every login, including the crafted one."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("DAHUA_MODE", "patched") == "vuln"

_AUTH_OK = '{"id": 1, "result": true, "session": 2089910329}'
_AUTH_ERR = ('{"id": 1, "result": false, "error": {"code": 268632085, '
             '"message": "Login failed, user or password not valid!"}}')


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
        self._send(404, "Not found")

    def do_POST(self):
        if self.path != "/RPC2_Login":
            self._send(404, "Not found")
            return
        raw = self._body()
        bypass = False
        try:
            params = (json.loads(raw) or {}).get("params", {}) or {}
            bypass = (params.get("loginType") == "Loopback"
                      and params.get("ipAddr") == "127.0.0.1")
        except (ValueError, AttributeError):
            bypass = False
        # Only the crafted Loopback identity is accepted, and only on vulnerable firmware.
        if VULN_MODE and bypass:
            self._send(200, _AUTH_OK, ct="application/json")
        else:
            self._send(200, _AUTH_ERR, ct="application/json")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
