#!/usr/bin/env python3
"""Mock for CVE-2019-16920 — D-Link routers unauthenticated command injection RCE.

Pure string/regex simulation of a shell command-substitution collapse. NO
subprocess / os.system / exec / eval / file I/O / real command execution.

Vuln mode  : recognises an injected `echo NOCTIS$()<token>` payload in the POST
             body, strips the empty `$()` (as a real shell would when expanding
             the substitution to nothing) and echoes the resulting contiguous
             NOCTIS<token> marker in a 200 response. The token is whatever the
             scanner sent this run, so the response is per-run, never a constant.
Patched    : reflects the payload verbatim with the `$()` left intact (no shell
             execution), so a contiguous marker never forms — detection fails.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("DLINK_ROUTERS_MODE", "patched") == "vuln"

# The collapse payload as the scanner sends it: NOCTIS$()<32 hex>. We capture
# the token so the echoed marker is the scanner's per-run value, not a constant.
PAYLOAD_RE = re.compile(r"NOCTIS\$\(\)([0-9a-f]{32})")


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

    def do_POST(self):
        if self.path != "/apply_sec.cgi":
            self._send(404, "Not found")
            return

        body = self._body()
        m = PAYLOAD_RE.search(body)

        if VULN_MODE and m:
            # Simulate the shell collapsing the empty command substitution:
            # "NOCTIS$()<token>" -> "NOCTIS<token>" (pure string op).
            token = m.group(1)
            collapsed = "NOCTIS" + token
            self._send(200, "<html><body>graph_auth\n" + collapsed + "\n</body></html>", "text/html")
        elif m:
            # Patched: no shell execution — reflect the payload with $() intact,
            # so the contiguous marker never forms.
            self._send(200, "<html><body>graph_auth\nNOCTIS$()" + m.group(1) + "\n</body></html>", "text/html")
        else:
            self._send(403, "Forbidden")

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
