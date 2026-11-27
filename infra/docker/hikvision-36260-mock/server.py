#!/usr/bin/env python3
# Mock for Hikvision webLanguage input-handling flaw (CVE-2021-36260).
#
# Modes (HIKVISION_MODE):
#   vuln     — MISHANDLES the <language> value: resolves the empty $() group away,
#              joining the marker and the per-run nonce. Pure string handling — it
#              runs NOTHING, reads/writes NO files, executes NO commands.
#   patched  — rejects the unauthenticated PUT with 403 (the fixed behaviour).
#   reflect  — echoes the raw body unchanged, with $() still intact (no join).
#   constant — always prints a fixed NOCTIS + 32×'a' banner (reviewer honeypot:
#              a constant marker that can never carry a given run's fresh nonce).
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

MODE = os.environ.get("HIKVISION_MODE", "patched")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/xml"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def do_PUT(self):
        if self.path != "/SDK/webLanguage":
            self._send(404, "Not found", ct="text/plain")
            return

        body = self._read_body()
        m = re.search(r"<language>(.*?)</language>", body, re.DOTALL)
        value = m.group(1) if m else ""

        if MODE == "vuln":
            # Mishandle the value: collapse the empty $() group away, joining the
            # literal marker and the nonce. Inert string handling only.
            processed = value.replace("$()", "")
            self._send(
                200,
                '<?xml version="1.0" encoding="UTF-8"?>'
                "<ResponseStatus><statusCode>1</statusCode>"
                "<statusString>OK</statusString>"
                "<language>%s</language></ResponseStatus>" % processed,
            )
        elif MODE == "reflect":
            # Echo the raw value unchanged — $() stays between marker and nonce.
            self._send(
                200,
                '<?xml version="1.0" encoding="UTF-8"?>'
                "<ResponseStatus><language>%s</language></ResponseStatus>" % value,
            )
        elif MODE == "constant":
            # Unconditional constant marker — never carries this run's nonce.
            self._send(
                200,
                '<?xml version="1.0" encoding="UTF-8"?>'
                "<ResponseStatus><language>NOCTIS%s</language></ResponseStatus>"
                % ("a" * 32),
            )
        else:  # patched
            self._send(
                403,
                '<?xml version="1.0" encoding="UTF-8"?>'
                "<ResponseStatus><statusCode>6</statusCode>"
                "<statusString>Invalid Operation</statusString></ResponseStatus>",
            )

    def do_GET(self):
        self._send(404, "Not found", ct="text/plain")

    def do_POST(self):
        self._send(404, "Not found", ct="text/plain")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
