#!/usr/bin/env python3
"""Mock Splunk 4.x web — multiple vulnerabilities (CVE-2011-4642/4643/4644/4778).

Vuln mode: GET /en-GB/account/login returns the login page together with an
anonymous `Set-Cookie: session_id_8000=...;` header — the precondition the
active exploit chain relies on and the exact signal the source NASL extracts
(eregmatch pattern "Set-Cookie: (session[^;]*);"). Patched mode: the login page
is served without that session cookie, so the pattern never matches.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("SPLUNK_MODE", "patched") == "vuln"

LOGIN_PAGE = (
    "<html><head><title>Login - Splunk</title></head>"
    "<body><form action='/en-GB/account/login' method='post'>"
    "<input name='username'><input type='password' name='password'>"
    "</form></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", cookie=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/en-GB/account/login":
            if VULN_MODE:
                # Affected Splunk hands out an anonymous session cookie.
                self._send(
                    200,
                    LOGIN_PAGE,
                    cookie="session_id_8000=6d9f2c1ab34e55f0a1; Path=/; HttpOnly",
                )
            else:
                # Fixed build: login page without a session cookie.
                self._send(200, LOGIN_PAGE)
            return
        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
