#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ROUNDCUBE_MODE", "patched") == "vuln"

# 1609 = version 1.6.9 (< 1.6.11, vulnerable)
# 1611 = version 1.6.11 (patched)
RCVERSION = "1609" if VULN_MODE else "1611"

HOMEPAGE = (
    "<!DOCTYPE html><html><head><title>Roundcube Webmail</title></head><body>"
    "<script>var rcmail_config = {\"rcversion\":RCVERSION_PLACEHOLDER, "
    "\"skin\":\"elastic\", \"standard_windows\":false};</script>"
    "<div id=\"loading\">Loading Roundcube...</div>"
    "</body></html>"
).replace("RCVERSION_PLACEHOLDER", RCVERSION)

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
        if self.path in ("/", "/?_task=login"):
            self._send(200, HOMEPAGE)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(302, b"", ct="text/plain")

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
