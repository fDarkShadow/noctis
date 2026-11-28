#!/usr/bin/env python3
# Mock for Micro Focus Operations Bridge Reporter — CVE-2021-22502.
#
# Vuln mode performs a PURE STRING SIMULATION of a shell evaluating the injected
# `userName` value: it removes empty command substitutions `$()` and the backtick
# wrappers, which collapses the probe's split marker ("NOCTIS$()<tok>") back into
# a contiguous "NOCTIS<tok>", then echoes that result in a 200 JSON body — exactly
# what a genuinely command-injectable OBR would surface. There is NO subprocess,
# os.system, exec, eval or file I/O: nothing from the request is executed.
#
# Patched mode leaves the payload entirely inert — it returns a benign 404 and
# never reflects the request body, so the collapse marker never appears.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("OBR_MODE", "patched") == "vuln"

ENDPOINT = "/AdminService/urest/v1/LogonResource"


def collapse_shell(value):
    """Inert simulation of a shell removing empty `$()` substitutions and the
    surrounding backticks. Pure string rewriting — executes nothing."""
    # Drop empty command substitutions: $() and ${} with nothing inside.
    collapsed = re.sub(r"\$\(\s*\)", "", value)
    collapsed = re.sub(r"\$\{\s*\}", "", collapsed)
    # Strip backtick command wrappers, keeping the inner text (which an
    # `echo` would print to stdout).
    collapsed = collapsed.replace("`", "")
    # Only the argument to `echo` would reach stdout.
    m = re.search(r"echo\s+(\S+)", collapsed)
    return m.group(1) if m else ""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if VULN_MODE and self.path == ENDPOINT:
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", errors="replace")
            # Pull the injected userName value and simulate shell evaluation.
            m = re.search(r'"userName"\s*:\s*"(.*?)"\s*,', raw)
            echoed = collapse_shell(m.group(1)) if m else ""
            body = (
                '{"status":"NOCTIS_OBR_CONFIRMED",'
                '"stdout":"' + echoed + '",'
                '"message":"LogonResource processed"}'
            )
            self._send(200, body)
        else:
            self._send(404, '{"error":"Not found"}')

    def do_GET(self):
        self._send(404, '{"error":"Not found"}')


if __name__ == "__main__":
    serve(Handler, HTTPServer)
