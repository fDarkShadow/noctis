#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SONICWALL_SMA_MODE", "patched") == "vuln"

# Paths as received verbatim by Python's HTTP server (no URL decoding)
SQLITE_PATH = "/tmp/temp.db%3f.1.1.1.1a-1.css"

SQLITE_BODY = (
    "SQLite format 3 [noctis-mock]\n"
    "sessionId=NOCTIS_DEMO_SESSION_abc123\n"
    "userId=admin\n"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == SQLITE_PATH:
            if VULN_MODE:
                self._send(200, SQLITE_BODY, "application/octet-stream")
            else:
                self._send(403, "Forbidden")
        else:
            self._send(404, "Not Found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
