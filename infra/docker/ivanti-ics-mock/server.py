#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("IVANTI_ICS_MODE", "patched") == "vuln"
VERSION = "22.7R2.3" if VULN_MODE else "22.7R2.5"

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
        if self.path.startswith("/dana-na/auth/url_default/welcome.cgi"):
            body = (
                f'<html><head><title>Ivanti Connect Secure</title></head><body>'
                f'<script>var productVersion = "{VERSION}";</script>'
                f'<h1>Ivanti Connect Secure</h1>'
                f'</body></html>'
            )
            self._send(200, body)
        elif self.path.startswith("/dana-na/"):
            self.send_response(301)
            self.send_header("Location", "/dana-na/auth/url_default/welcome.cgi")
            self.end_headers()
        else:
            self._send(200, "<html><title>Ivanti Connect Secure</title></html>")

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
