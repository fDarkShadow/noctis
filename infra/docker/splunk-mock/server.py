#!/usr/bin/env python3
"""Mock Splunk 4.x web — search-action CSRF/RCE (CVE-2011-4642/4643/4644/4778).

Reproduces the full chain the source NASL (2011/gb_splunk_multiple_vuln.nasl)
exploits, so detection is proven by code execution, not by a session cookie:

  1. GET /en-GB/account/login
       both modes serve the login page with an anonymous
       `Set-Cookie: session_id_8000=<token>;` header. The real 4.2.5 fix kept
       anonymous session cookies, so a cookie alone proves nothing — which is
       exactly why the feed must not report on it.

  2. POST /en-GB/api/search/jobs
       VULN mode: when X-Splunk-Session matches the cookie token, the crafted
       `mappy`/`eval` search payload "runs" and the command output is staged
       for the static .tmp path (executed=True). Returns 200 (job created).
       PATCHED mode: the search job is accepted (200) but the payload is NOT
       executed — the fixed build validates the request — so nothing is staged.

  3. GET /en-US/static/@105575/js/.tmp
       VULN mode after a successful search job: returns `uid=0(root) gid=0(root)`
       (the `id` output the payload wrote). PATCHED mode: 404.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SPLUNK_MODE", "patched") == "vuln"

# Anonymous session cookie the login page hands out (both modes). The value is
# alphanumeric so the NASL token regex `=([a-zA-Z0-9]+)` captures it.
SESSION_TOKEN = "6d9f2c1ab34e55f0a1"
SESSION_COOKIE = "session_id_8000=" + SESSION_TOKEN

LOGIN_PAGE = (
    "<html><head><title>Login - Splunk</title></head>"
    "<body><form action='/en-GB/account/login' method='post'>"
    "<input name='username'><input type='password' name='password'>"
    "</form></body></html>"
)

# Output the injected `id` command writes to the static .tmp file on a
# successful (vulnerable) search-job dispatch.
ID_OUTPUT = "uid=0(root) gid=0(root) groups=0(root)\n"

# Set once a vulnerable search job executes the payload; gates the .tmp path.
_executed = threading.Event()


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
            # Both modes issue the anonymous session cookie (the real fix kept
            # it); the cookie is a precondition, never proof.
            self._send(
                200,
                LOGIN_PAGE,
                cookie=SESSION_COOKIE + "; Path=/; HttpOnly",
            )
            return

        if self.path == "/en-US/static/@105575/js/.tmp":
            # Only a vulnerable instance that ran the payload has staged output.
            if VULN_MODE and _executed.is_set():
                self._send(200, ID_OUTPUT, ct="text/plain")
            else:
                self._send(404, "Not found")
            return

        self._send(404, "Not found")

    def do_POST(self):
        if self.path == "/en-GB/api/search/jobs":
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            xsplunk = self.headers.get("X-Splunk-Session", "")
            cookie = self.headers.get("Cookie", "")
            # The exploit only works when the replayed session token is valid.
            session_ok = xsplunk == SESSION_TOKEN and SESSION_TOKEN in cookie
            if VULN_MODE and session_ok:
                # Affected build: the crafted search runs the command and writes
                # its output to the exposed static .tmp file.
                _executed.set()
            # Both modes acknowledge the (accepted) search-job request.
            self._send(201, '{"sid":"1700000000.1"}', ct="application/json")
            return

        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
