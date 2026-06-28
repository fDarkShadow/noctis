#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

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

def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv

if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
