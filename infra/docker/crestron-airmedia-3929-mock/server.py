#!/usr/bin/env python3
"""Mock for CVE-2019-3929 — Barco/AWIND OEM (Crestron AirMedia) unauthenticated
OS command injection in /cgi-bin/file_transfer.cgi.

vuln  : file_transfer.cgi passes a POST parameter into a shell command without
        sanitisation. We model a real shell: URL-decode the body, find the
        injected `echo NOCTIS$()<token>`, evaluate the empty command
        substitution `$()` (which collapses to nothing) and echo the joined
        result `NOCTIS<token>` back. Non-trivial TN: the token is whatever the
        scanner sent this run, never a constant, and `$()` is actually removed.
patched: the parameter is sanitised; file_transfer.cgi rejects the request
        with 403 and never reaches a shell.

The behaviour is deliberately realistic so the negative tests are non-trivial:
  * patched               -> 403, no marker                              (clean)
  * no injection in body  -> 200 directory listing, no marker            (clean)
  * reflecting (RELFECT)  -> echoes body verbatim with `$()` intact      (clean)
  * constant marker (CONST) -> emits a fixed token, never the run token  (clean)
"""
import os
import re
from urllib.parse import unquote_plus
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("AIRMEDIA_3929_MODE", "patched")
VULN = MODE == "vuln"
# Cheating-mock modes used only by the adversarial negative tests.
REFLECT = MODE == "reflect"   # dumb reflector: returns the body with $() intact
CONST = MODE == "const"       # returns a hardcoded constant marker

# Matches the inert injected payload `echo NOCTIS$()<hex token>` after the body
# has been URL-decoded. Group 1 is the per-run hex token.
INJ_RE = re.compile(r"NOCTIS\$\(\)([0-9a-f]+)")

DIR_LISTING = (
    "<html><head><title>AirMedia File Transfer</title></head>"
    "<body><h3>Index of /tmp</h3><ul><li>config</li><li>log</li></ul></body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode("latin-1", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Boa/0.94.14rc21")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(n).decode("latin-1", "replace") if n else ""

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/cgi-bin/file_transfer.cgi":
            self._send(404, "Not found")
            return

        raw = self._read_body()
        decoded = unquote_plus(raw)

        if not (VULN or REFLECT or CONST):
            # Patched: input sanitised / endpoint locked down.
            self._send(403, "Forbidden")
            return

        if REFLECT:
            # Inert reflector: echoes input back, `$()` NOT evaluated.
            self._send(200, "path=" + decoded)
            return

        if CONST:
            # Emits a fixed marker that can never equal the scanner's run token.
            self._send(200, "result: NOCTIS" + ("0" * 32))
            return

        # Vulnerable: emulate the shell evaluating the injected command.
        m = INJ_RE.search(decoded)
        if m:
            token = m.group(1)
            # `$()` is an empty command substitution -> collapses to "".
            # `echo NOCTIS$()<token>` therefore prints the joined marker.
            self._send(200, "result: NOCTIS" + token + "\n")
        else:
            # No injection -> ordinary directory listing, no marker.
            self._send(200, DIR_LISTING)

    def do_GET(self):
        self._send(200, DIR_LISTING)


if __name__ == "__main__":
    serve(Handler, HTTPServer)
