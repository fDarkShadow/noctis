#!/usr/bin/env python3
"""Mock Apache Struts2 — S2-057 OGNL namespace injection (CVE-2018-11776).

When `alwaysSelectFullNamespace` is enabled and the namespace is derived from
the request URL without validation, a vulnerable Struts2 evaluates the URL
namespace segment as an OGNL expression. The classic PoC places the expression
in the action-chain path:

    GET /struts2-showcase/${(A*B)}/actionChain1.action

A vulnerable instance evaluates the arithmetic and emits a 302 whose Location
reflects the computed product (e.g. ${(42*37)} -> /struts2-showcase/1554/...).

Vuln mode: parse the benign ${(A*B)} arithmetic from the namespace and 302 to
    the computed product — exactly what a vulnerable Struts namespace eval does.
Patched mode: the namespace is NOT evaluated — the literal expression is kept
    (404 Not Found), so no computed product is ever reflected.

The probe is sent verbatim over tcp_connect, so self.path preserves the raw
`$ { } ( ) *` characters, which we parse here directly. The operands are
random per run, so reflecting a hardcoded constant would not be detected: the
mock must genuinely evaluate the operands it is given.
"""
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("STRUTS_MODE", "patched") == "vuln"

# ${(A*B)} in the URL namespace segment — parens optional, around a benign
# integer multiplication. Matched against the raw (un-decoded) request path.
OGNL_RE = re.compile(r"/struts2-showcase/\$\{\(?\s*(\d+)\s*\*\s*(\d+)\s*\)?\}/")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        m = OGNL_RE.search(self.path)

        if VULN_MODE and m:
            # Vulnerable Struts2 evaluates the OGNL namespace arithmetic and
            # redirects to the computed value.
            product = int(m.group(1)) * int(m.group(2))
            self._send(
                302,
                "",
                extra={"Location": "/struts2-showcase/%d/actionChain1.action" % product},
            )
            return

        if self.path.startswith("/struts2-showcase/") and self.path.endswith(".action") and "${" not in self.path:
            # Benign showcase action — normal page.
            self._send(200, "<html><title>Struts2 Showcase</title><body>Welcome!</body></html>")
            return

        # Patched: the OGNL expression in the namespace is not evaluated — the
        # literal path does not resolve to an action (no computed redirect).
        self._send(404, "Not Found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
