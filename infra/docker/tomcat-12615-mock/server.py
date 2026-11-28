#!/usr/bin/env python3
"""Mock for CVE-2017-12615 — Apache Tomcat writable DefaultServlet (PUT).

vuln mode    : DefaultServlet readonly=false. An unauthenticated PUT writes the
               request body into an in-memory webroot keyed by path and returns
               201 Created; a later GET of that path serves the stored body
               verbatim (so the client's own uploaded token is reflected back).
patched mode : PUT is rejected (405 Method Not Allowed); the path is never
               created, so a GET returns 404.
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("TOMCAT_MODE", "patched") == "vuln"

# In-memory webroot shared across requests: path -> stored bytes.
STORE = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "Apache-Coyote/1.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def do_PUT(self):
        body = self._read_body()
        if VULN_MODE:
            # readonly=false: write the uploaded (benign) file into the webroot.
            STORE[self.path] = body
            self._send(201, "")
        else:
            # readonly default: default servlet refuses writes.
            self._send(405, "Method Not Allowed")

    def do_GET(self):
        if self.path in STORE:
            # Serve back exactly what was written — reflects the client's token.
            self._send(200, STORE[self.path])
        elif self.path in ("/", "/index.html"):
            self._send(200, b"<html><body><h1>Apache Tomcat</h1></body></html>", "text/html")
        else:
            self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
