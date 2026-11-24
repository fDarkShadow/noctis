#!/usr/bin/env python3
"""Mock for CVE-2013-10043. Ported alongside the OpenVAS NASL detection (GPL-2.0-only).
vuln and patched behaviours are both realistic so the TN is non-trivial. The vuln branch
requires the astiumnls session cookie on the logon POST and dashboard GET, so the feed's
cookie-extraction + Cookie-header steps are actually exercised."""
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN = os.environ.get("CVE_2013_10043_MODE", "patched") == "vuln"
SESSION = "a1b2c3d4e5"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _start(self, code):
        self._body = b""
        self._code = code
        self._hdrs = []

    def _h(self, k, v):
        self._hdrs.append((k, v))

    def _finish(self, body):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        self.send_response(self._code)
        for k, v in self._hdrs:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("latin-1", "replace") if n else ""

    def _route(self, method):
        path = self.path
        body = self._read_body()
        vuln = VULN
        cookie = self.headers.get("Cookie", "")
        has_session = ("astiumnls=" + SESSION) in cookie
        if (vuln and method == 'GET' and path.startswith('/index.php')):
            self._start(302)
            self._h('Location', '/index.php?astiumnls=' + SESSION)
            self._h('Set-Cookie', 'astiumnls=' + SESSION + '; path=/')
            self._finish('')
            return
        # Login bypass: require the session cookie and the SQLi payload, as a real target would.
        if (vuln and method == 'POST' and path == '/en/logon.php'
                and has_session and "user_name=system%27" in body):
            self._start(302)
            self._h('Location', '/en/database/dashboard.php')
            self._finish('')
            return
        if (vuln and path == '/en/database/dashboard.php' and has_session):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish("<html><head><title>Astium</title></head><body><h1>system admin's Dashboard</h1></body></html>\n")
            return
        if (method == 'GET' and path.startswith('/index.php')):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish('<html><head><title>Astium VoIP PBX</title></head><body>Login</body></html>\n')
            return
        if (method == 'POST' and path == '/en/logon.php'):
            self._start(200)
            self._h('Content-Type', 'text/html')
            self._finish('<html><body>Invalid credentials</body></html>\n')
            return
        if (path == '/en/database/dashboard.php'):
            self._start(401)
            self._h('Content-Type', 'text/html')
            self._h('WWW-Authenticate', 'Basic realm="Astium"')
            self._finish('<html><body>401 Authorization Required</body></html>\n')
            return
        # default
        self._start(404)
        self._h("Content-Type", "text/plain")
        self._finish("Not found\n")

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
