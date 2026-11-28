#!/usr/bin/env python3
# Dedicated mock for CVE-2019-7192 (QNAP Photo Station unauthenticated RCE).
#
# Vuln mode simulates — by pure string manipulation, with NO subprocess,
# os.system, exec, or file I/O — a shell collapsing the empty command
# substitution `$()` in the injected `echo NOCTIS$()<token>` payload and
# reflecting the collapsed marker. Patched mode leaves the payload inert
# (returns it verbatim, `$()` intact) so the detection match never fires.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("QNAP_7192_MODE", "patched") == "vuln"

# Matches the injected probe: echo NOCTIS$()<32 hex chars>
PROBE_RE = re.compile(r"echo NOCTIS\$\(\)([0-9a-f]{32})")


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", "replace") if length > 0 else ""

    def do_GET(self):
        if self.path.split("?")[0] == "/":
            self._send(200, "<html><body><h1>QNAP Photo Station</h1></body></html>", "text/html")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path != "/photo/p/api/album.php":
            self._send(404, "Not found")
            return

        body = self._read_body()
        m = PROBE_RE.search(body)
        if VULN_MODE and m:
            # Pure string simulation of the shell collapse: `$()` evaluates to
            # the empty string, so `NOCTIS$()<token>` becomes `NOCTIS<token>`.
            collapsed = "NOCTIS" + m.group(1)
            self._send(200, "<?xml version=\"1.0\"?><root>" + collapsed + "</root>", "text/xml")
        elif VULN_MODE:
            # Vulnerable but no probe present: ordinary album API response.
            self._send(200, "<?xml version=\"1.0\"?><root><status>0</status></root>", "text/xml")
        else:
            # Patched: input is not passed to a shell. Echo it back inert, with
            # `$()` intact, so the collapse marker can never appear.
            self._send(200, "<?xml version=\"1.0\"?><root><error>invalid album</error></root>", "text/xml")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
