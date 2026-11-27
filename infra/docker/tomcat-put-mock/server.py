#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("TOMCAT_MODE", "patched") == "vuln"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Server", "Apache-Coyote/1.1")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _drain_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            self.rfile.read(length)

    def do_GET(self):
        self._send(200, b"<html><body><h1>Apache Tomcat</h1></body></html>", "text/html")

    def do_PUT(self):
        self._drain_body()
        # Vulnerable: partial PUT with Content-Range to .session files is accepted
        has_range = "Content-Range" in self.headers
        if VULN_MODE and self.path.endswith(".session") and has_range:
            self._send(201, "NOCTIS_TOMCAT_OK")
        else:
            self._send(405, "Method Not Allowed")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
