#!/usr/bin/env python3
# Mock for ASUS GT-AC2900 appGet.cgi authentication bypass (CVE-2021-32030).
#
# The privileged admin handler (get_cfg_clientlist) is gated on a valid
# session. On a VULNERABLE router, the asus_token comparison mishandles a token
# whose value begins with a NUL byte, so such a token is accepted as an admin
# session and the handler returns the genuine client-list payload. A request
# WITHOUT the NUL-byte token (no token / ordinary invalid token) is still
# rejected even on the vulnerable mock — the bypass is the NUL byte, not a
# constant. A PATCHED router rejects every unauthenticated request.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ASUS_MODE", "patched") == "vuln"

# Genuine authenticated appGet.cgi client-list response the privileged handler
# emits. Detection keys on get_cfg_clientlist / alias / model_name (real
# fields); the NOCTIS marker is only a corroborating breadcrumb, never matched.
CLIENTLIST = (
    '{"get_cfg_clientlist":[{"alias":"","model_name":"GT-AC2900",'
    '"name":"GT-AC2900","mac":"AA:BB:CC:DD:EE:FF","ip":"192.168.1.1"},'
    '{"alias":"desktop","model_name":"","name":"workstation",'
    '"mac":"11:22:33:44:55:66","ip":"192.168.1.42"}],'
    '"NOCTIS_ASUS_CONFIRMED":"1"}'
)

LOGIN = '{"error_status":"8","login_page":"Login.asp"}'


def _asus_token(cookie):
    for part in (cookie or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "asus_token":
            return v
    return None


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
        if self.path.startswith("/appGet.cgi") and "get_cfg_clientlist" in self.path:
            token = _asus_token(self.headers.get("Cookie"))
            # The CVE: a NUL byte in the token is accepted as an admin session.
            bypass = token is not None and "\x00" in token
            if VULN_MODE and bypass:
                self._send(200, CLIENTLIST, ct="application/json")
            else:
                # No valid session (or patched firmware) -> reject.
                self._send(401, LOGIN, ct="application/json")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
