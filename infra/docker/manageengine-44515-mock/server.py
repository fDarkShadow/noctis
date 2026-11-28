#!/usr/bin/env python3
"""Mock Zoho ManageEngine Desktop Central — CVE-2021-44515 auth bypass.

Vuln mode: a forged request to /STATE_ID/<n>/agentLogUploader carrying a
"Cookie: STATE_COOKIE=..." header is treated as a valid server-side state and
is handed a FRESH, random UEMJSESSIONID session cookie with HTTP 200 and an
empty body — the authentication-bypass behaviour. Any request WITHOUT the
forged STATE_COOKIE (including the identical path with no cookie) is refused
with 403 and no session cookie.

Patched mode: the forged STATE_ID request is rejected (403) and never issues a
session cookie.

The session id is regenerated per request, so it differs across runs — exactly
as a real appliance issues a distinct session each time.
"""
import os
import re
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("MANAGEENGINE_DC_MODE", "patched") == "vuln"

# Forged agent-log-uploader state path: /STATE_ID/<digits>/agentLogUploader
STATE_PATH_RE = re.compile(r"^/STATE_ID/\d+/agentLogUploader$")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _forged_state_request(self):
        """True when this is the crafted STATE_ID path with a STATE_COOKIE."""
        cookie = self.headers.get("Cookie", "")
        return bool(STATE_PATH_RE.match(self.path)) and "STATE_COOKIE=" in cookie

    def do_GET(self):
        if VULN_MODE and self._forged_state_request():
            # Vulnerable: forged state accepted → issue a fresh authenticated
            # session. Empty body, one Set-Cookie with a random session id.
            session = secrets.token_hex(16)
            self._send(
                200,
                "",
                extra_headers={
                    "Set-Cookie": f"UEMJSESSIONID={session}; Path=/; HttpOnly",
                },
            )
            return
        # Everything else (and all requests in patched mode): no session.
        self._send(403, "Forbidden")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
