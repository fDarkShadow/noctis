#!/usr/bin/env python3
"""Inert MobileIron Core/Connector mock for CVE-2020-15505.

Pure string simulation — no subprocess, eval, file I/O, sockets or real
deserialization. Vuln mode simulates the fails-open servlet filter: the
unauthenticated /mifs/.;/services/LogService bypass path is reachable and
reflects the caller-supplied `probe` marker (as a real exposed instance would
process and echo the request through the fails-open path). Patched mode blocks
that path (403). Neither mode reflects on a normal /mifs/ path, so a feed's
control request stays clean.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs

from mocklib import serve

VULN_MODE = os.environ.get("MOBILEIRON_MODE", "patched") == "vuln"


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

    def _marker(self):
        qs = parse_qs(urlsplit(self.path).query)
        return (qs.get("probe") or [""])[0]

    def _handle(self):
        path = urlsplit(self.path).path
        # The security-filter bypass path to the Hessian LogService sink.
        if "services/LogService" in path:
            if VULN_MODE:
                marker = self._marker()
                body = (
                    "NOCTIS_MOBILEIRON_CONFIRMED\n"
                    "MobileIron LogService (Hessian) reached via /mifs/.;/ "
                    "fails-open filter.\n"
                    f"probe={marker}\n"
                )
                self._send(200, body, ct="application/x-hessian")
            else:
                # Patched: the servlet filter no longer fails open.
                self._send(403, "403 Forbidden")
            return
        # Normal /mifs/ paths: benign, never reflect the marker (so a feed's
        # control request cannot see it).
        self._send(404, "404 Not Found")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self._handle()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
