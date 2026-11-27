#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("VERSA_MODE", "patched") == "vuln"

ACTUATOR_BODY = b'{"_links":{"self":{"href":"/portalapi/actuator","templated":false},"heapdump":{"href":"/portalapi/actuator/heapdump","templated":false},"env":{"href":"/portalapi/actuator/env","templated":false},"health":{"href":"/portalapi/actuator/health","templated":false}}}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json", extra_headers=None):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path != "/portalapi/actuator":
            self._send(404, b"Not found")
            return

        connection_hdr = self.headers.get("Connection", "")
        bypass_active = "X-Real-Ip" in connection_hdr or "x-real-ip" in connection_hdr.lower()

        if VULN_MODE and bypass_active:
            self._send(200, ACTUATOR_BODY, extra_headers={"EECP-CSRF-TOKEN": "noctis-csrf-token"})
        else:
            self._send(401, b'{"error": "Unauthorized"}')


if __name__ == "__main__":
    serve(Handler, HTTPServer)
