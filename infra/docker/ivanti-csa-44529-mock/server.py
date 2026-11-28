#!/usr/bin/env python3
# Mock for Ivanti EPM Cloud Services Appliance code injection (CVE-2021-44529).
#
# The feed injects an inert command-substitution probe into the Cookie header:
#     c=echo NOCTIS$()<token>
# A real vulnerable appliance would EVALUATE that injected code; this mock does a
# pure STRING simulation of what a shell/eval does to an empty command
# substitution "$()" — it never spawns a subprocess, never touches the filesystem,
# never calls os.system/exec/eval. It only rewrites a string.
#
#   vuln    : collapse "$()" (empty substitution → ""), run the leading `echo`,
#             and reflect the resulting CONTIGUOUS marker ("NOCTIS<token>").
#   patched : reflect the cookie value verbatim, inert — "$()" stays in place, so
#             the marker is never contiguous and the feed's regex gate fails.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("IVANTI_CSA_MODE", "patched") == "vuln"

PAGE = (
    "<html><head><title>Ivanti Cloud Services Appliance</title></head>"
    "<body><h1>Ivanti Cloud Services Appliance</h1>"
    "<pre>{out}</pre></body></html>"
)


def _simulate(cookie_value):
    """Pure string sim of evaluating `echo ...` with an empty command sub."""
    collapsed = cookie_value.replace("$()", "")  # empty substitution → ""
    collapsed = collapsed.strip()
    if collapsed.startswith("echo "):
        return collapsed[5:].strip()
    return ""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.split("?")[0] != "/client/index.php":
            self._send(404, "Not found")
            return

        cookie = self.headers.get("Cookie", "")
        m = re.search(r"(?:^|;)\s*c=([^;]*)", cookie)
        cookie_value = m.group(1) if m else ""

        if VULN_MODE:
            # Code injection path: the injected `echo` is evaluated, so the
            # empty "$()" collapses and the marker is emitted contiguously.
            out = _simulate(cookie_value)
        else:
            # Patched: the cookie is NOT evaluated. Reflect it inert, so the
            # literal "$()" remains and the contiguous-marker gate fails.
            out = cookie_value

        self._send(200, PAGE.format(out=out))

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
