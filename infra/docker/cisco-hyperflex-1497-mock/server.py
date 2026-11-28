#!/usr/bin/env python3
"""Mock for Cisco HyperFlex HX Data Platform command-injection RCE (CVE-2021-1497).

Vuln mode: pure STRING SIMULATION of a shell processing the injected auth change
password. It url-decodes the password, removes empty command substitutions `$()`
(exactly what a real shell does — command substitution of an empty command expands
to nothing), and echoes back the `echo` argument. This reproduces the collapse that
makes `NOCTIS$()<token>` become the contiguous `NOCTIS<token>` marker the feed
matches. NO subprocess / os.system / exec / eval / file I/O is used — the payload is
never executed, only string-manipulated.

Patched mode: the payload is left inert — the endpoint reflects the password verbatim
(the `$()` stays between NOCTIS and the token, so the marker never appears
contiguously) — so every detection step fails and no finding is produced.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("HYPERFLEX_MODE", "patched") == "vuln"


def shell_collapse(cmd):
    """String-only simulation of a shell running `cmd`.

    Empty command substitutions `$()` expand to nothing; the argument of the first
    `echo` is returned as its stdout. No real execution occurs.
    """
    collapsed = cmd.replace("$()", "")
    idx = collapsed.find("echo ")
    if idx < 0:
        return ""
    arg = collapsed[idx + len("echo "):]
    # stop at the next shell command separator
    for sep in (";", "&", "|", "\n"):
        pos = arg.find(sep)
        if pos >= 0:
            arg = arg[:pos]
    return arg.strip()


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
        if self.path != "/auth/change":
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(raw, keep_blank_values=True)
        password = params.get("password", [""])[0]

        if VULN_MODE:
            # Vulnerable: password reaches a shell. Simulate (string-only) the
            # command running and reflect its stdout.
            output = shell_collapse(password)
            self._send(200, "auth change output: %s\n" % output)
        else:
            # Patched: payload left completely inert — reflected verbatim, the
            # empty `$()` is NOT collapsed, so the marker never lands contiguously.
            self._send(200, "auth change rejected for input: %s\n" % password)

    def do_GET(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
