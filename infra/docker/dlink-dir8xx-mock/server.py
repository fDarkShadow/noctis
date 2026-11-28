#!/usr/bin/env python3
"""Mock for CVE-2018-6530 — D-Link DIR-8xx unauthenticated SOAP command injection.

Vuln mode models the vulnerable firmware: /soap.cgi is reachable pre-authentication,
parses the `service` query parameter, and returns a SOAP-shaped response that reflects
the requested service value (the behaviour the real CGI exhibits before it hands the
value to a shell). Patched mode requires authentication / has no such handler and
returns 403, so no detection step can succeed.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from mocklib import serve

VULN_MODE = os.environ.get("DLINK_DIR8XX_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n:
            self.rfile.read(n)

    def _handle(self):
        self._drain_body()
        parsed = urlparse(self.path)
        if parsed.path != "/soap.cgi":
            self._send(404, "Not found")
            return

        service = (parse_qs(parsed.query).get("service") or [""])[0]

        if not VULN_MODE:
            # Patched / non-vulnerable: endpoint rejects unauthenticated SOAP calls.
            self._send(403, "Forbidden")
            return

        # Vulnerable firmware: unauthenticated, parses `service`, reflects it in a
        # SOAP envelope. The reflected value is what detection keys on (plus the
        # SOAP shape); the marker below is only a human breadcrumb, never matched on.
        envelope = (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">\n'
            "  <SOAP-ENV:Body>\n"
            "    <SOAP-ENV:Fault>\n"
            "      <faultcode>SOAP-ENV:Client</faultcode>\n"
            "      <faultstring>no handler registered for service: {svc}</faultstring>\n"
            "    </SOAP-ENV:Fault>\n"
            "  </SOAP-ENV:Body>\n"
            "</SOAP-ENV:Envelope>\n"
            "<!-- NOCTIS_DLINK_DIR8XX_CONFIRMED -->\n"
        ).format(svc=service)
        self._send(200, envelope, ct="text/xml")

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
