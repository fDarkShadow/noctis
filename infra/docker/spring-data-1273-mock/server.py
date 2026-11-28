#!/usr/bin/env python3
# Mock for Spring Data Commons SpEL injection (CVE-2018-1273).
#
# This is an INERT string simulation of a SpEL evaluator for exactly ONE payload
# shape — a  T(java.lang.String).valueOf('A').concat('B')  concatenation of two
# single-quoted literals supplied inside the  username[...]  property path. The
# vuln mock recognises that pattern and returns the *joined* literals, which is
# what a real SpEL binder would produce. There is NO SpEL engine, NO Java, NO
# subprocess/exec/eval of attacker input and NO file I/O: the only "evaluation"
# is a regex extraction of two literals and a Python string concatenation.
#
# The patched mock rejects the malformed property path with a binding error that
# echoes the raw (unevaluated) path — the two literals stay separated by the
# SpEL syntax, so the contiguous marker never appears and detection fails.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SPRINGDATA_MODE", "patched") == "vuln"

# username[ ... valueOf('<lit1>').concat('<lit2>') ... ]
CONCAT_RE = re.compile(r"valueOf\('([^']*)'\)\.concat\('([^']*)'\)")


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
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def do_POST(self):
        if self.path.split("?")[0] != "/users":
            self._send(404, "Not Found")
            return

        body = self._read_body()
        m = CONCAT_RE.search(body)

        if VULN_MODE and m:
            # A real SpEL binder would evaluate the expression: join the two
            # literals. This is the ONLY place "evaluation" happens — pure
            # string concatenation of the two captured literals.
            joined = m.group(1) + m.group(2)
            out = (
                "NOCTIS_SPRINGDATA_CONFIRMED\n"
                "org.springframework.expression result: " + joined + "\n"
            )
            self._send(200, out)
        else:
            # Patched: the property path is rejected / reflected UNEVALUATED.
            # The raw path (literals still separated by the SpEL syntax) is
            # echoed in a binding error, so no contiguous marker is produced.
            self._send(
                400,
                "Bad Request: invalid property path in request: " + body + "\n",
            )

    def do_GET(self):
        self._send(404, "Not Found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
