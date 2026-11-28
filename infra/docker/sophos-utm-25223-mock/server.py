#!/usr/bin/env python3
# Pure-simulation mock for Sophos UTM WebAdmin preauth RCE (CVE-2020-25223).
#
# DETECTION, NOT EXPLOITATION: no shell, no subprocess, no file I/O. The vuln
# branch *simulates* the shell's handling of the injected `echo` argument with
# pure string/regex operations and reflects the result. Modes (SOPHOS_UTM_MODE):
#
#   vuln           — evaluate the injected echo: collapse the empty command
#                    substitution  $()  away, reflecting the CONTIGUOUS argument.
#                    Only reflects when the  $()  collapse primitive is actually
#                    present (a benign echo with no $() reflects nothing) — so
#                    detection genuinely depends on the collapse technique.
#   patched        — /var returns a benign 403; nothing is reflected.
#   reflect_intact — cheating control: reflects the argument VERBATIM, leaving
#                    "$()" between the halves (no collapse). Must NOT be detected.
#   constant       — cheating control: always reflects a fixed constant marker,
#                    never the request's per-run token. Must NOT be detected.
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("SOPHOS_UTM_MODE", "patched")

# Capture the argument of the injected `echo` (letters/digits plus the shell
# command-substitution chars $ ( ) ) — e.g. "NOCTIS$()<32 hex>".
ECHO_RE = re.compile(r"echo\s+([A-Za-z0-9$()]+)")

CONST_MARKER = "NOCTIS" + ("0" * 32)  # fixed, never matches a fresh per-run token


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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        return self.rfile.read(length).decode("utf-8", errors="replace") if length else ""

    def do_POST(self):
        if self.path != "/var":
            self._send(404, '{"error":"Not found"}')
            return

        if MODE == "patched":
            # Patched WebAdmin rejects the unauthenticated JSON-RPC call.
            self._send(403, '{"error":"forbidden"}')
            return

        body = self._read_body()
        m = ECHO_RE.search(body)
        if not m:
            # No injected echo at all — nothing to reflect.
            self._send(200, '{"objs":[],"out":""}')
            return

        arg = m.group(1)

        if MODE == "vuln":
            # Simulate shell evaluation. The empty command substitution $()
            # expands to nothing, so the two halves become contiguous. Reflect
            # ONLY when the collapse primitive is present (genuine technique).
            if "$()" not in arg:
                self._send(200, '{"objs":[],"out":""}')
                return
            out = arg.replace("$()", "")
        elif MODE == "reflect_intact":
            # Cheat: echo the argument verbatim, $() left intact (no shell eval).
            out = arg
        elif MODE == "constant":
            # Cheat: always the same constant, ignoring the request's token.
            out = CONST_MARKER
        else:
            self._send(200, '{"objs":[],"out":""}')
            return

        payload = (
            '{"objs":[{"FID":"init"}],"out":"' + out + '",'
            '"note":"NOCTIS_SOPHOS_UTM_CONFIRMED"}'
        )
        self._send(200, payload)

    def do_GET(self):
        self._send(404, '{"error":"Not found"}')


if __name__ == "__main__":
    serve(Handler, HTTPServer)
