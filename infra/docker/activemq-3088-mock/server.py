#!/usr/bin/env python3
"""Mock for Apache ActiveMQ Fileserver arbitrary file write (CVE-2016-3088).

Vuln mode faithfully reproduces the real consequence: an unauthenticated HTTP
PUT under /fileserver/ stores the request body in memory, and a subsequent GET
of the same path serves that exact body back (PUT -> 204, GET -> 200). It does
NOT fabricate a constant marker — it echoes whatever bytes were PUT, so the
per-run token the feed writes is what comes back. A cheating constant response
or a patched broker therefore cannot satisfy the write-then-read differential.

Patched mode rejects the write entirely (PUT -> 403) and never serves the file
(GET -> 404), so no finding is produced.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ACTIVEMQ_MODE", "patched") == "vuln"

# In-memory store of files written via PUT /fileserver/... (vuln mode only).
STORE = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Jetty(7.6.9.v20130131)")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_PUT(self):
        if VULN_MODE and self.path.startswith("/fileserver/"):
            length = int(self.headers.get("Content-Length", 0) or 0)
            data = self.rfile.read(length) if length else b""
            STORE[self.path] = data
            # Jetty's default PUT handler answers 204 No Content.
            self._send(204)
        else:
            # Patched broker: Fileserver removed / read-only -> write rejected.
            self._send(403, "Forbidden")

    def do_GET(self):
        if VULN_MODE and self.path.startswith("/fileserver/") and self.path in STORE:
            self._send(200, STORE[self.path])
        elif self.path == "/" or self.path.startswith("/admin"):
            self._send(200, "<html><title>Apache ActiveMQ</title></html>", "text/html")
        else:
            self._send(404, "Not found")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)  # HTTP:80 + HTTPS:443 (cert from the base image)
