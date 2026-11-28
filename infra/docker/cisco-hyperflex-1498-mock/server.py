#!/usr/bin/env python3
# Dedicated mock for CVE-2021-1498 (Cisco HyperFlex HX Data Platform command
# injection on POST /storfs-asup). Independent of the CVE-2021-1497 mock.
#
# Vuln mode  : PURE STRING SIMULATION of a shell evaluating the injected command.
#              The only thing the "shell" does is collapse an empty command
#              substitution `$()` to nothing (exactly what a real shell does),
#              then reflect the result. No subprocess, os.system, exec, eval or
#              file I/O — the payload is never executed, only string-rewritten.
#              Collapsing `echo NOCTIS$()<token>` → `NOCTIS<token>` makes the
#              contiguous per-run marker appear in the response.
# Patched mode: leaves the payload inert (reflects it verbatim, `$()` intact), so
#              the contiguous marker never forms and detection fails.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("HYPERFLEX_MODE", "patched") == "vuln"


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

    def do_POST(self):
        if self.path == "/storfs-asup":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            if VULN_MODE:
                # Simulate a shell: collapse empty command substitution `$()`.
                # Pure string rewrite — nothing is executed.
                collapsed = body.replace("$()", "")
                self._send(200, "NOCTIS_HYPERFLEX storfs-asup handler\n" + collapsed)
            else:
                # Patched: payload inert, reflected verbatim with `$()` intact.
                self._send(200, "storfs-asup handler\n" + body)
        else:
            self._send(404, "Not found")

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
