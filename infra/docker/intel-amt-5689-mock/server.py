#!/usr/bin/env python3
# Intel AMT mock for CVE-2017-5689 (empty-Digest-response auth bypass).
#
# /index.htm is a Digest-protected AMT management page.
#   - No Authorization header               -> 401 + WWW-Authenticate: Digest challenge
#   - Digest with a NON-empty response hash  -> 401 (wrong credentials)
#   - Digest with an EMPTY response (response="") :
#       VULN_MODE   -> 200 + admin management page  (length-only strncmp bug)
#       patched     -> 401                           (bug fixed)
#
# The empty-vs-nonempty differential is the whole point: a server that returned
# 200 for *any* auth would also 200 the wrong-response control, which the feed
# requires to be a 401.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("AMT_MODE", "patched") == "vuln"

CHALLENGE = ('Digest realm="Digest:A9EBD000000000000000000000000000", '
             'nonce="noctis", qop="auth", stale="false"')

ADMIN_PAGE = (
    "<html><head><title>Intel(R) Active Management Technology</title></head>"
    "<body><h1>Intel(R) Active Management Technology</h1>"
    "<p>System Status</p>"
    "<table><tr><td>Power</td><td>On</td></tr>"
    "<tr><td>Remote Control</td><td>Available</td></tr></table>"
    "</body></html>"
)

# Captures the quoted value of response= (empty string when response="").
RESP_RE = re.compile(r'response\s*=\s*"([^"]*)"', re.IGNORECASE)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Intel(R) Active Management Technology 9.0.0")
        for k, v in (extra or {}):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _challenge(self):
        self._send(401, "Unauthorized", ct="text/plain",
                   extra=[("WWW-Authenticate", CHALLENGE)])

    def do_GET(self):
        if self.path.split("?", 1)[0] not in ("/index.htm", "/logon.htm", "/"):
            self._send(404, "Not found", ct="text/plain")
            return

        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("digest"):
            self._challenge()
            return

        m = RESP_RE.search(auth)
        response_hash = m.group(1) if m else None

        # The CVE trigger: an empty response hash authenticates on vulnerable
        # firmware (length-only comparison). Any non-empty hash is "wrong".
        if VULN_MODE and response_hash == "":
            self._send(200, ADMIN_PAGE)
        else:
            self._challenge()

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
