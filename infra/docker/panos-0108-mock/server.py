#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("PANOS_0108_MODE", "patched") == "vuln"

ZTP_BODY = (
    "<html><head><title>Zero Touch Provisioning (ZTP)</title></head>"
    "<body>Zero Touch Provisioning</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # self.path is the raw undecoded path as received from the socket
        if "%252e%252e" in self.path and "ztp_gate.php" in self.path:
            if VULN_MODE:
                self._send(200, ZTP_BODY)
            else:
                self._send(403, "Forbidden")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
