#!/usr/bin/env python3
# Mock for CVE-2017-9791 (Apache Struts2 S2-053 — OGNL expression injection in
# the Struts 1 plugin / Struts1 integration example app).
#
# DETECTION target for the benign-arithmetic differential feed. The feed POSTs a
# benign OGNL arithmetic expression %{(A*B)} (random operands per run) to
# /integration/saveGangster.action and recomputes A*B itself. No command
# execution, no file access — arithmetic only.
#
# Vuln mode:    emulates the S2-053 forced OGNL evaluation: when the `name` field
#               carries %{(A*B)}, the server evaluates the arithmetic and reflects
#               the computed product. Because it computes from the operands the
#               client actually sent, a per-run-random product is reflected and a
#               hardcoded constant is never used — so the feed's recompute-and-
#               compare check passes only on genuine evaluation.
# Patched mode: the OGNL is NOT evaluated — the literal expression %{(A*B)} is
#               echoed back unchanged (the Gangster is "added" but the key is not
#               interpreted), so the computed product never appears and detection
#               fails. A non-/integration path 404s in both modes.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve   # provided by noctis/py-mock-base

VULN_MODE = os.environ.get("STRUTS_9791_MODE", "patched") == "vuln"

# Benign arithmetic OGNL expression: %{(<digits>*<digits>)}
OGNL_ARITH = re.compile(r"%\{\((\d+)\*(\d+)\)\}")

GANGSTER_FORM = (
    "<!DOCTYPE html>\n<html><head><title>Struts1 Integration - Gangster</title></head>\n"
    "<body><h1>Gangster Registration</h1>\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_gangster(self):
        return self.path.rstrip("/") == "/integration/saveGangster.action"

    def do_GET(self):
        if self._is_gangster():
            self._send(200, GANGSTER_FORM + "<p>Register a new gangster.</p>\n</body></html>\n")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        body = self._read_body()
        if not self._is_gangster():
            self._send(404, "Not found")
            return

        try:
            decoded = body.decode("utf-8", "replace")
        except Exception:
            decoded = ""

        m = OGNL_ARITH.search(decoded)
        if m is None:
            # No OGNL arithmetic expression in the request at all.
            self._send(200, GANGSTER_FORM + "<p>Gangster added successfully.</p>\n</body></html>\n")
            return

        a, b = int(m.group(1)), int(m.group(2))

        if VULN_MODE:
            # Vulnerable Struts2 S2-053: the Struts 1 plugin forces a second OGNL
            # evaluation of the attacker-controlled key, so %{(A*B)} is evaluated
            # and the integer product is reflected. Computed from the operands the
            # client sent — never a constant — so the value differs every run.
            product = a * b
            reflected = (
                GANGSTER_FORM
                + "<p>Gangster "
                + str(product)
                + " added successfully.</p>\n"
                + "<!-- NOCTIS_STRUTS_S2053_CONFIRMED result=" + str(product) + " -->\n"
                + "</body></html>\n"
            )
            self._send(200, reflected)
        else:
            # Patched Struts: the key is treated as a literal string, OGNL is NOT
            # evaluated, so the expression is echoed back verbatim and the product
            # never appears.
            literal = m.group(0)
            self._send(
                200,
                GANGSTER_FORM
                + "<p>Gangster " + literal + " added successfully.</p>\n"
                + "</body></html>\n",
            )


if __name__ == "__main__":
    serve(Handler, HTTPServer)   # HTTP:80 + HTTPS:443 (cert from the base image)
