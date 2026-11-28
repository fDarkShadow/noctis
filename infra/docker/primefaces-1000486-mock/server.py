#!/usr/bin/env python3
# Inert mock for CVE-2017-1000486 (Primetek Primefaces 5.x EL injection RCE).
#
# Vuln mode  : PURE STRING-SIMULATION of EL evaluation for THIS payload shape only.
#              It recognises the ${'literal'}${'literal'}... pattern and concatenates
#              the inner literals — exactly what a real EL engine would do with
#              ${'NOCTIS'}${'<tok>'} — so the response carries the CONTIGUOUS marker.
#              NO real EL/JSF/Java, NO eval/exec, NO subprocess, NO file I/O: it only
#              joins string literals it matched with a regex.
# Patched mode: reflects the pfdrid value VERBATIM (unevaluated). The two literals
#              stay separated by EL syntax ('}${'), so the contiguous marker and the
#              feed's regex NOCTIS[0-9a-f]{32} never appear -> no finding. This also
#              doubles as the "cheating raw-reflect" negative: echoing the payload
#              back is not evaluation, so it must still yield zero findings.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PRIMEFACES_MODE", "patched") == "vuln"

ENDPOINT = "/javax.faces.resource/dynamiccontent.properties.xhtml"
# One ${'...'} EL string literal.
EL_LITERAL = re.compile(r"\$\{'([^']*)'\}")


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

    @staticmethod
    def _extract_pfdrid(body):
        # pfdrid is the trailing form field; its value may contain ${ } ' chars, so
        # pull everything after "pfdrid=" up to the next & (there is none after it).
        idx = body.find("pfdrid=")
        if idx < 0:
            return None
        val = body[idx + len("pfdrid="):]
        amp = val.find("&")
        if amp >= 0:
            val = val[:amp]
        return val.strip()

    def do_POST(self):
        if self.path != ENDPOINT:
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        pfdrid = self._extract_pfdrid(body)
        if pfdrid is None:
            self._send(400, "Bad Request")
            return

        if VULN_MODE:
            # Simulate EL evaluation: concatenate the inner literals of each ${'...'}.
            literals = EL_LITERAL.findall(pfdrid)
            evaluated = "".join(literals) if literals else pfdrid
            # Vulnerable dynamic-content endpoint returns the evaluated expression.
            self._send(200, evaluated, ct="text/plain")
        else:
            # Patched: no EL evaluation — reflect the raw (unevaluated) value.
            self._send(200, "unresolved resource: " + pfdrid, ct="text/plain")

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
