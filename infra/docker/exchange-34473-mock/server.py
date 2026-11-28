#!/usr/bin/env python3
"""Mock Microsoft Exchange — CVE-2021-34473 ProxyShell pre-auth path confusion.

Pure string simulation. No subprocess, no file I/O, no outbound sockets.

vuln mode     the Autodiscover frontend "fails open" when the request target
              carries the ProxyShell path confusion (an embedded "@" in the
              query of /autodiscover/autodiscover.json). On that path it echoes
              the request query back (so the scanner's per-run marker is
              reflected). Every other path — including the normal, non-confused
              Autodiscover path used as the scanner's control — requires auth
              and reflects nothing.

patched mode  the confusion is rejected: /autodiscover/autodiscover.json always
              requires authentication and never reflects the query, on the
              confusion path and the control path alike.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("EXCHANGE_MODE", "patched") == "vuln"

AUTODISCOVER = "/autodiscover/autodiscover.json"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _auth_required(self):
        # Backend protected: real Exchange returns 401 for unauthenticated
        # Autodiscover without the path confusion. Reflects nothing.
        self._send(
            401,
            "<html><body>401 - Unauthorized: Access is denied.</body></html>",
            extra_headers={"WWW-Authenticate": "Negotiate"},
        )

    def do_GET(self):
        raw = self.path  # request target, undecoded (%3F / @ preserved)
        path, _, query = raw.partition("?")

        if path != AUTODISCOVER:
            self._send(404, "<html><body>Not Found</body></html>")
            return

        # ProxyShell path confusion: an embedded "@" (raw or %40-encoded) in the
        # Autodiscover query makes a vulnerable frontend route to the backend.
        has_confusion = ("@" in query) or ("%40" in query)

        if VULN_MODE and has_confusion:
            # Fails open to the backend MAPI/HTTP endpoint and echoes the query,
            # so the scanner's per-run marker is reflected back verbatim.
            body = (
                "Exchange MAPI/HTTP Connectivity Endpoint\n"
                "Microsoft.Exchange.Clients.Owa2.Server.Core.OwaADUserNotFoundException\n"
                "NOCTIS_EXCHANGE_CONFIRMED\n"
                "reflected-request-query: " + query + "\n"
            )
            self._send(200, body, ct="text/plain")
            return

        # Patched server, or the control path (no confusion): auth required,
        # nothing reflected.
        self._auth_required()

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
