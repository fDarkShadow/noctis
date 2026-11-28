#!/usr/bin/env python3
"""Mock for CVE-2023-38035 — Ivanti Sentry MICS authentication bypass.

The MICS System Manager admin API must require an authenticated admin session.
On a vulnerable host a permissive Apache configuration lets UNAUTHENTICATED
requests reach it, so a protected endpoint answers with a privileged response.

Modes (IVANTI_SENTRY_38035_MODE):
  vuln     — unauth request to the protected endpoint returns 200 with the
             "MICS System Manager" marker AND reflects this run's probe nonce.
  patched  — same endpoint returns 403 (access denied): no marker, no reflection.
  const    — a blanket/constant mock: returns the marker but a FIXED body that
             never carries the caller's nonce (used to prove the detection is not
             fooled by a constant privileged-looking page).

Pure string handling — no command execution, no file writes.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from mocklib import serve

MODE = os.environ.get("IVANTI_SENTRY_38035_MODE", "patched")
VULN_MODE = MODE == "vuln"
CONST_MODE = MODE == "const"

# Protected MICS System Manager admin endpoint (the bypass target).
MICS_ADMIN = "/mics/services/MICSLogService"
# A genuinely authenticated-only action: rejected even on a vulnerable host.
# Used as a negative control (not every MICS path is reachable unauth).
MICS_AUTHED_ONLY = "/mics/services/MICSConfigService"


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

    def _nonce(self):
        """Benign probe nonce carried in a header or query parameter."""
        hdr = self.headers.get("X-Noctis-Probe", "")
        if hdr:
            return hdr
        qs = parse_qs(urlparse(self.path).query)
        return qs.get("noctisProbe", [""])[0]

    def _handle(self):
        path = urlparse(self.path).path

        # Authenticated-only admin action: always rejected (negative control).
        if path == MICS_AUTHED_ONLY:
            self._send(401, "Unauthorized\n")
            return

        if path == MICS_ADMIN:
            if CONST_MODE:
                # Blanket mock: privileged-looking marker, but a constant body
                # that does NOT echo the caller's per-run nonce.
                self._send(
                    200,
                    "MICS System Manager\nstatus: ok\n",
                    "text/xml",
                )
                return
            if VULN_MODE:
                # Bypass active: privileged response reflecting this run's nonce.
                nonce = self._nonce()
                body = (
                    "NOCTIS_IVANTI_SENTRY_CONFIRMED\n"
                    "MICS System Manager\n"
                    "role: administrator\n"
                    "probe: %s\n" % nonce
                )
                self._send(200, body, "text/xml")
                return
            # Patched: Apache restricts the admin API.
            self._send(403, "Forbidden\n")
            return

        # Generic Ivanti Sentry landing page.
        self._send(200, "<html><title>Ivanti Sentry</title></html>", "text/html")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
