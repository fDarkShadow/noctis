#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("FORTIMANAGER_MODE", "patched") == "vuln"
VERSION = "7.4.3" if VULN_MODE else "7.4.5"

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
        if self.path.startswith("/p/login/") or self.path.startswith("/ui/login"):
            body = (
                f'<html><head><title>FortiManager</title></head><body>'
                f'<span class="logo-text">FortiManager</span>'
                f'<div class="ver">{VERSION}</div>'
                f'</body></html>'
            )
            self._send(200, body)
        elif self.path.startswith("/logincheck"):
            self._send(200, "<html><title>FortiManager</title></html>")
        elif self.path == "/":
            self.send_response(302)
            self.send_header("Location", "/p/login/")
            self.end_headers()
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
