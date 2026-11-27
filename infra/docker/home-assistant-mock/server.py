#!/usr/bin/env python3
"""Mock Home Assistant Supervisor — CVE-2023-27482 proxy auth bypass.

Vuln mode: a request whose (un-normalised) path carries an encoded traversal
(.%252e/) to /supervisor/info or /core/info reaches the privileged endpoint
and returns {"result":"ok",...}. Patched mode: such traversal paths are
rejected (401).
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("HA_MODE", "patched") == "vuln"


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

    def do_GET(self):
        raw = self.path  # un-normalised; keeps %252e / %09 verbatim

        # Fingerprint endpoint — present in both modes.
        if raw.split("?", 1)[0] == "/api/hassio/app/entrypoint.js":
            self._send(200, "// Home Assistant frontend entrypoint", "application/javascript")
            return

        # Encoded-traversal to a privileged Supervisor endpoint.
        is_traversal = ("%252e" in raw or "%2e" in raw or "%09" in raw) and (
            "supervisor/info" in raw or "core/info" in raw
        )
        if is_traversal:
            if VULN_MODE:
                self._send(
                    200,
                    '{"result":"ok","data":{"version":"2023.03.0",'
                    '"supervisor_token":"NOCTIS_HASSIO_ADMIN_TOKEN"}}',
                )
            else:
                self._send(401, '{"result":"error","message":"Unauthorized"}')
            return

        self._send(404, '{"result":"error","message":"Not Found"}')

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
