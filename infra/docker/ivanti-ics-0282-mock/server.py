#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ICS_MODE", "patched") == "vuln"
VERSION = "22.7R2.4" if VULN_MODE else "22.7R2.5"

WELCOME_HTML = """<!DOCTYPE html>
<html><head><title>Ivanti Connect Secure</title></head>
<body>
<h1>Ivanti Connect Secure</h1>
<p>Version {v} - Ivanti Connect Secure VPN Gateway</p>
<p>Please sign in to continue.</p>
</body></html>""".format(v=VERSION)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in (
            "/dana-na/auth/url_default/welcome.cgi",
            "/dana-na/auth/url_6/welcome.cgi",
        ):
            self._send(200, WELCOME_HTML)
        else:
            self._send(404, "Not Found", "text/plain")

    def do_POST(self):
        self._send(404, "Not Found", "text/plain")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
