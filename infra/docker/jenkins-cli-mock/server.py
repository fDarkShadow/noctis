#!/usr/bin/env python3
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("JENKINS_MODE", "patched") == "vuln"

# Simulated /etc/passwd first line returned in the "No such agent" error
_PASSWD_LINE = "root:x:0:0:root:/root:/bin/bash"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Jenkins", "2.441" if VULN_MODE else "2.442")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length:
            self.rfile.read(content_length)

        if self.path.startswith("/cli"):
            side = self.headers.get("Side", "")
            if side == "download":
                # Acknowledge download-side connection
                self._send(200, b"", "application/octet-stream")
            elif side == "upload":
                if VULN_MODE:
                    # Simulate @/etc/passwd expansion: Jenkins reads file and echoes
                    # it in the "No such agent" error message
                    body = (
                        f'CLI error: No such agent "{_PASSWD_LINE}\n'
                        f'bin:x:1:1:bin:/bin:/sbin/nologin"'
                    )
                    self._send(200, body)
                else:
                    # Patched: @-argument expansion is disabled
                    self._send(200, "CLI error: No such agent \"@/etc/passwd\" (file expansion disabled)")
            else:
                self._send(400, "Missing Side header")
        else:
            self._send(404, "Not found")

    def do_GET(self):
        if self.path.startswith("/api/json"):
            version = "2.441" if VULN_MODE else "2.442"
            self._send(200, f'{{"_class":"hudson.model.Hudson","version":"{version}"}}', "application/json")
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
